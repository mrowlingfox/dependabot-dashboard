from gql import gql, Client
from gql.transport.aiohttp import AIOHTTPTransport
from retry import retry
import json
import concurrent.futures
from github import Github
from github.GithubException import RateLimitExceededException
import psycopg2
from datetime import date, datetime
import os

DB_USER = os.environ["DB_USER"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
DH_HOST = os.environ["DB_HOST"]
HOST = os.environ["GH_HOST"]
GH_TOKEN = os.environ["GH_TOKEN"]
GH_ORG = os.environ.get("GH_ORG", "fsa-streamotion")
LOCAL_CACHE = os.environ.get("LOCAL_CACHE") # Set to True to use local cache, helpful for local debugging
TABLE_NAME = os.environ.get("TABLE_NAME", "dependabot_alerts")


def create_file_if_not_exists(file_path):
    if not os.path.exists(os.path.dirname(file_path)):
        os.makedirs(os.path.dirname(file_path))
    if not os.path.exists(file_path):
        with open(file_path, 'w') as file:
            json.dump({}, file)


def memoize_and_cache_on_disk(cache_file):
    create_file_if_not_exists(cache_file)
    def memoize_and_cache_on_disk_decorator(func):
        def memoize_and_cache_on_disk_wrapper(*args, **kwargs):
            if not LOCAL_CACHE:
                return func(*args, **kwargs)
            try:
                with open(cache_file, 'rb') as cache:
                    cache_dict = json.load(cache)
            except FileNotFoundError:
                cache_dict = {}
            key = json.dumps({
                "args": args,
                "kwargs": kwargs
            })
            if key in cache_dict.keys():
                print("Cache hit for: ", key)
                return cache_dict[key]
            else:
                print("Cache miss for: ", key)
                result = func(*args, **kwargs)
                cache_dict[key] = result
                with open(cache_file, 'w') as cache:
                    json.dump(cache_dict, cache)
                return result
        return memoize_and_cache_on_disk_wrapper
    return memoize_and_cache_on_disk_decorator

def initialize_db(db_connection):
    print("Init DB")
    try:
        cursor = db_connection.cursor()

        postgres_create_table = f""" 
            create table if not exists {TABLE_NAME} (
                snapshot timestamp,
                gh_repo varchar(100),
                gh_org varchar(30),
                created_at timestamp,
                fixed_at timestamp,
                alert_number int,
                state varchar(10),
                dismissed_at timestamp,
                dismiss_reason varchar(300),
                dismisser varchar(30),
                vuln_ghsa_id varchar(30),
                vuln_severity varchar(15),
                vuln_summary text,
                vuln_package varchar(100),
                fix_pr_number int,
                fix_pr_title text,
                fix_merged_at timestamp
            );
            """
        cursor.execute(postgres_create_table)

        db_connection.commit()
    except (Exception, psycopg2.Error) as error:
        print(f"Failed to initialize {TABLE_NAME} table: ", error)

def parse_alert(alert, gh_org, gh_repo, snapshot_date):
    snapshot_timestamp = datetime.strptime(
            str(snapshot_date), "%Y-%m-%d").strftime("%Y-%m-%dT00:00:00Z")
    repo = gh_org + "/" + gh_repo
    org = gh_org
    created_at = alert.get("createdAt")
    fixed_at = alert.get("fixedAt")

    alert_number = alert.get("number")
    state = alert.get("state")
    dismissed_at = alert.get("dismissedAt")
    dismiss_reason = alert.get("dismissReason")
    dismisser = None
    if alert.get("dismisser") is not None:
        dismisser = alert.get("dismisser").get("login")

    vuln_ghsa_id = alert.get("securityVulnerability", {}).get("advisory").get("ghsaId")
    vuln_severity = alert.get("securityVulnerability", {}).get("severity")
    vuln_summary = alert.get("securityVulnerability", {}).get("advisory").get("summary")
    vuln_package = alert.get("securityVulnerability", {}).get("package").get("name")

    fix_pr_number = None
    fix_pr_title = None
    fix_merged_at = None

    if alert.get("dependabotUpdate") is not None:
        if alert.get("dependabotUpdate").get("pullRequest") is not None:
            fix_pr_number = alert.get("dependabotUpdate").get("pullRequest").get("number")
            fix_pr_title = alert.get("dependabotUpdate").get("pullRequest").get("title")
            fix_merged_at = alert.get("dependabotUpdate").get("pullRequest").get("mergedAt")

    if state == "FIXED" or state == "DISMISSED":
        tmp_now = datetime.strptime(
            str(snapshot_date), "%Y-%m-%d")
        if fixed_at is not None:
            tmp_fixed_at = datetime.strptime(fixed_at, "%Y-%m-%dT%H:%M:%SZ")
            if tmp_fixed_at >= tmp_now:
                state = "OPEN"
        if dismissed_at is not None:
            tmp_dismissed_at = datetime.strptime(dismissed_at, "%Y-%m-%dT%H:%M:%SZ")
            if tmp_dismissed_at >= tmp_now:
                state = "OPEN"
    
    db_values = (snapshot_timestamp, repo, org, created_at, fixed_at, alert_number, state, dismissed_at, dismiss_reason,
                dismisser, vuln_ghsa_id, vuln_severity, vuln_summary, vuln_package, fix_pr_number, fix_pr_title, fix_merged_at)
    
    return db_values

def bulk_insert_into_db(db_connection, db_values):
    try:
        insert_query = f"""
            insert into {TABLE_NAME} (
                snapshot,
                gh_repo,
                gh_org,
                created_at,
                fixed_at,
                alert_number,
                state,
                dismissed_at,
                dismiss_reason,
                dismisser,
                vuln_ghsa_id,
                vuln_severity,
                vuln_summary,
                vuln_package,
                fix_pr_number,
                fix_pr_title,
                fix_merged_at
            ) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """

        cursor = db_connection.cursor()
        cursor.executemany(insert_query, db_values)
        db_connection.commit()
    except (Exception, psycopg2.Error) as error:
        print("Failed to insert records into dependabot_alerts table: ", error)

@memoize_and_cache_on_disk(cache_file="cache/get_repos.cache")
def get_repos(gh_token, gh_org):
    print("Getting repos for: " + gh_org)
    g = Github(gh_token)
    org = g.get_organization(gh_org)
    repos = org.get_repos()
    return [ repo.full_name for repo in repos ]

def concatenate_lists(list1, list2):
    return list1 + list2


def gql_client(host, gh_token):
    headers = {
        "Authorization": "Bearer " + gh_token,
        "Accept": "application/vnd.github.v4.idl"
    }

    # Select your transport with a defined url endpoint
    transport = AIOHTTPTransport(url=host+"/graphql", headers=headers)
    # Create a GraphQL client using the defined transport
    return Client(transport=transport, fetch_schema_from_transport=True)

def build_query(gh_repo, gh_org, first=100, after=None):
    if after is not None:
        q_str = f"first:{first}, after: \"{after}\""
    else:
        q_str = f"first:{first}"
    query = f"""
    {{
        repository(name: "{gh_repo}", owner: "{gh_org}") {{
            vulnerabilityAlerts({q_str}) {{
                pageInfo {{
                    startCursor
                    hasNextPage
                    endCursor
                }}
                nodes {{
                    createdAt
                    fixedAt
                    number
                    dependabotUpdate {{
                        pullRequest {{
                            number
                            title
                            mergedAt
                        }}
                    }}
                    state
                    dismissedAt
                    dismisser {{
                        login
                    }}
                    dismissReason
                    securityVulnerability {{
                        severity
                        advisory {{
                            ghsaId
                            summary
                        }}
                        package {{
                            name
                        }}
                    }}
                }}
            }}
        }}
    }}
    """
    return gql(query)

@retry(backoff=2, tries=5)
def execute_with_retry(client, query):
    return client.execute(query)

def execute_gql_query_with_paging(client, gh_repo, gh_org, first, after=None):
    query = build_query(gh_repo, gh_org, first, after)
    result = execute_with_retry(client, query)
    alerts = result.get("repository").get("vulnerabilityAlerts").get("nodes")

    has_next_page = result.get("repository").get("vulnerabilityAlerts").get("pageInfo").get("hasNextPage")
    
    if has_next_page:
        end_cursor = result.get("repository").get("vulnerabilityAlerts").get("pageInfo").get("endCursor")
        next_alerts = execute_gql_query_with_paging(client, gh_repo, gh_org, first, end_cursor)
        alerts = concatenate_lists(alerts, next_alerts)
    
    return alerts


@memoize_and_cache_on_disk(cache_file="cache/get_alerts.cache")
@retry(RateLimitExceededException, backoff=2, tries=5)
def get_alerts(host, gh_token, gh_org, gh_repo):
    # Handle pagination
    client = gql_client(host, gh_token)

    alerts = execute_gql_query_with_paging(client, gh_repo, gh_org, 100)

    return alerts

def process_repo(gh_org, repo, db_connection):
    org = repo.split("/")[0]
    repo_name = repo.split("/")[1]
    alerts = get_alerts(HOST, GH_TOKEN, org, repo_name)
    snapshot_date = date.today()
    print(f"[+] Processing {repo_name}")
    print(f"[+] Found {len(alerts)} alerts")
    if alerts:
        print(f"[+] Inserting into database")
        database_inserts = [ parse_alert(alert, gh_org, repo_name, snapshot_date) for alert in alerts]
        bulk_insert_into_db(db_connection, database_inserts)

def main():
    db_connection = psycopg2.connect(user=DB_USER,
                                      password=DB_PASSWORD,
                                      host=DH_HOST,
                                      port="5432",
                                      database="dependabot")
    initialize_db(db_connection)
    repos = get_repos(gh_token=GH_TOKEN, gh_org=GH_ORG)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(process_repo, [GH_ORG] * len(repos), repos, [db_connection] * len(repos))

if __name__ == "__main__":
    main()