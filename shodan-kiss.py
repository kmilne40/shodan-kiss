import os
import shodan
import json
import logging

# Configure logging
logging.basicConfig(
    filename='shodan_tool.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

SHODAN_API_KEY = "YOUR-API-KEY-HERE"  # Replace with your Shodan API key

try:
    api = shodan.Shodan(SHODAN_API_KEY)
except Exception as e:
    print("Error initializing Shodan API:", e)
    exit(1)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


class ShodanQueryBuilder:
    """
    Manages the base query and filters. Supports AND/OR logic.
    """
    def __init__(self):
        self.base_query = ""
        self.full_query = ""

    def set_base_query(self, base):
        self.base_query = base.strip()
        self.full_query = self.base_query

    def reset(self):
        self.base_query = ""
        self.full_query = ""

    def is_empty(self):
        return not self.full_query.strip()

    def add_filter(self, f, operator="AND"):
        """
        Add a filter with a specified operator (AND/OR).
        For AND: just append with a space.
        For OR: wrap existing query and new filter in parentheses and insert OR.
        """
        f = f.strip()
        if not f:
            return
        if self.is_empty():
            # If query empty, just start with this filter
            self.full_query = f
        else:
            if operator.upper() == "AND":
                self.full_query = f"{self.full_query} {f}"
            elif operator.upper() == "OR":
                self.full_query = f"({self.full_query}) OR ({f})"

    def get_query(self):
        # If no base and no filters, default to "*"
        if self.is_empty():
            return "*"
        return self.full_query.strip()


query_builder = ShodanQueryBuilder()
results_cache = []


def main_menu():
    while True:
        clear_screen()
        print_ascii_banner()
        print("KISS: Kev's Interactive Shodan Simplifier")
        print("==========================================")
        print("1. Choose a target type (domain, organization, network, IP, or nothing)")
        print("2. Add filters (port, vulnerabilities, etc.) with AND/OR")
        print("3. Finalize query, edit manually if needed, and execute")
        print("4. Save last results to file")
        print("5. View and add trending CVE-based queries")
        print("6. Manage Shodan Alerts")
        print("7. View Stats/Facets for the current query")
        print("8. Start a new clean query")
        print("9. Exit")
        print("==========================================")
        choice = input("Choose an option (1-9): ")

        if choice == "1":
            choose_target_type()
        elif choice == "2":
            add_filters_menu()
        elif choice == "3":
            finalize_and_execute_query()
        elif choice == "4":
            save_results_to_file()
        elif choice == "5":
            add_trending_cve_filter()
        elif choice == "6":
            manage_alerts_menu()
        elif choice == "7":
            view_stats()
        elif choice == "8":
            start_new_query()
        elif choice == "9":
            exit_program()
        else:
            print("Invalid choice. Press Enter to continue...")
            input()


def print_ascii_banner():
    # ASCII banner for "KISS" using '@'
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    print("@@@@     K   I   S   S       @@@@")
    print("@@@@                         @@@@")
    print("@@@@   Kev's Interactive     @@@@")
    print("@@@@   Shodan Simplifier     @@@@")
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n")


def start_new_query():
    query_builder.reset()
    global results_cache
    results_cache = []
    print("A new, clean query has been started. Previous query and results cleared.")
    input("Press Enter to return to main menu...")


def choose_target_type():
    clear_screen()
    print("Target Type Selection")
    print("======================")
    print("1. Domain (e.g., hostname:example.com)")
    print("2. Organization (e.g., org:\"Google LLC\")")
    print("3. Network (CIDR) (e.g., net:192.168.1.0/24)")
    print("4. IP Address (e.g., 8.8.8.8)")
    print("5. Nothing (empty base query)")
    print("======================")
    choice = input("Choose a target type (1-5): ")

    if choice == "1":
        domain = input("Enter the domain (e.g., example.com): ").strip()
        query_builder.set_base_query(f"hostname:{domain}")
    elif choice == "2":
        org = input("Enter the organization name (e.g., Google LLC): ").strip()
        query_builder.set_base_query(f'org:"{org}"')
    elif choice == "3":
        network = input("Enter the network CIDR (e.g., 192.168.1.0/24): ").strip()
        query_builder.set_base_query(f"net:{network}")
    elif choice == "4":
        ip_address = input("Enter the IP address (e.g., 8.8.8.8): ").strip()
        query_builder.set_base_query(ip_address)
    elif choice == "5":
        query_builder.set_base_query("")
    else:
        print("Invalid choice.")
        input("Press Enter to continue...")
        return

    print(f"Current query: {query_builder.get_query()}")
    input("Press Enter to return to main menu...")


def add_filters_menu():
    while True:
        clear_screen()
        print("Filter Options")
        print("===================")
        print("1. Add port filter (e.g., port:22)")
        print("2. Add vulnerability (e.g., vuln:CVE-2023-12345)")
        print("3. Add key phrase (e.g., \"admin\")")
        print("4. Add product (e.g., product:Apache)")
        print("5. Add country (e.g., country:US)")
        print("6. Add city (e.g., city:\"New York\")")
        print("7. Add OS (e.g., os:\"Windows 10\")")
        print("8. Add raw filter (expert mode)")
        print("9. Return to main menu")
        print("===================")
        choice = input("Choose a filter type (1-9): ")

        if choice == "9":
            break

        operator = input("Combine this filter with the existing query using AND or OR? [AND/OR]: ").strip().upper()
        if operator not in ["AND", "OR"]:
            operator = "AND"

        filter_str = ""
        if choice == "1":
            port = input("Enter the port number (e.g., 22): ").strip()
            filter_str = f"port:{port}"
        elif choice == "2":
            vuln = input("Enter the CVE (e.g., CVE-2023-12345): ").strip()
            filter_str = f"vuln:{vuln}"
        elif choice == "3":
            phrase = input("Enter the key phrase (e.g., admin): ").strip()
            if " " in phrase and not (phrase.startswith('"') and phrase.endswith('"')):
                phrase = f"\"{phrase}\""
            filter_str = phrase
        elif choice == "4":
            product = input("Enter the product name (e.g., Apache): ").strip()
            filter_str = f"product:{product}"
        elif choice == "5":
            country = input("Enter the country code (e.g., US): ").strip()
            filter_str = f"country:{country}"
        elif choice == "6":
            city = input("Enter the city (e.g., \"New York\"): ").strip()
            if " " in city and not (city.startswith('"') and city.endswith('"')):
                city = f"\"{city}\""
            filter_str = f"city:{city}"
        elif choice == "7":
            os_name = input("Enter the operating system (e.g., \"Windows 10\"): ").strip()
            if " " in os_name and not (os_name.startswith('"') and os_name.endswith('"')):
                os_name = f"\"{os_name}\""
            filter_str = f"os:{os_name}"
        elif choice == "8":
            filter_str = input("Enter the raw filter string (e.g., title:\"Login Page\"): ").strip()
        else:
            print("Invalid choice. Press Enter to continue...")
            input()
            continue

        if filter_str:
            query_builder.add_filter(filter_str, operator=operator)
            print(f"Filter added. Current Query: {query_builder.get_query()}")
        else:
            print("No filter added.")

        input("Press Enter to continue...")


def add_trending_cve_filter():
    clear_screen()
    print("Fetching trending queries from Shodan...")
    try:
        data = api.queries()
        queries = data.get('matches', [])
        cve_queries = [q for q in queries if "CVE-" in q.get('query', '')]

        if not cve_queries:
            print("No trending CVE-based queries found at this time.")
            input("Press Enter to return to main menu...")
            return

        print("Trending CVE Queries:")
        for i, q in enumerate(cve_queries[:10]):
            print(f"{i+1}. Title: {q['title']} | Query: {q['query']}")

        choice = input(f"Select a query to add (1-{min(len(cve_queries),10)}) or press Enter to cancel: ").strip()
        if not choice.isdigit():
            return
        idx = int(choice)
        if 1 <= idx <= len(cve_queries[:10]):
            chosen_query = cve_queries[idx-1]['query']
            operator = input("Combine this CVE query with the existing query using AND or OR? [AND/OR]: ").strip().upper()
            if operator not in ["AND", "OR"]:
                operator = "AND"
            query_builder.add_filter(chosen_query, operator=operator)
            print(f"Trending CVE Query added. Current Query: {query_builder.get_query()}")
        else:
            print("Invalid selection.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

    input("Press Enter to return to main menu...")


def finalize_and_execute_query():
    clear_screen()
    q = query_builder.get_query()
    print("Final Query (Before Execution):")
    print("======================")
    print(q)
    print("======================")
    edit_choice = input("Would you like to (E)dit, (R)un, or (C)ancel? [E/R/C]: ").strip().upper()
    if edit_choice == "E":
        # Allow manual editing
        print("Edit the query below. Press Enter to submit.")
        new_q = input(f"Query [{q}]: ").strip()
        if new_q:
            q = new_q
    elif edit_choice == "C":
        return

    # Now q is final, run the query
    execute_query(q)


def execute_query(final_query):
    clear_screen()
    print(f"Executing Shodan Query: {final_query}")
    print("======================")

    page = 1
    global results_cache
    results_cache = []  # clear previous

    while True:
        try:
            results = api.search(final_query, page=page)
            total = results.get('total', 0)
            matches = results.get('matches', [])
            if page == 1:
                print(f"Total results found: {total}")

            if not matches and page == 1:
                print("No results found.")
                input("Press Enter to return to main menu...")
                return
            elif not matches:
                print("No more results.")
                input("Press Enter to return to main menu...")
                return

            # Display results
            for match in matches:
                ip = match.get('ip_str', 'N/A')
                port = match.get('port', 'N/A')
                org = match.get('org', 'N/A')
                print(f"IP: {ip}, Port: {port}, Org: {org}")

            # Store results
            results_cache.extend(matches)

            # Pagination
            print("\n[P]revious Page  |  [N]ext Page  |  [M]ain Menu")
            nav = input("Choose an action (P/N/M): ").lower()
            if nav == 'p':
                if page > 1:
                    page -= 1
                else:
                    print("Already on the first page.")
                    input("Press Enter to continue...")
            elif nav == 'n':
                if len(matches) > 0:
                    page += 1
                else:
                    print("No more pages.")
                    input("Press Enter to continue...")
            elif nav == 'm':
                return
            else:
                print("Invalid choice. Returning to main menu...")
                input("Press Enter to continue...")
                return

        except shodan.APIError as e:
            print(f"Shodan API Error: {e}")
            logging.error(f"Shodan API Error: {e}")
            input("Press Enter to return to main menu...")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            logging.error(f"Unexpected error: {e}")
            input("Press Enter to return to main menu...")
            return


def save_results_to_file():
    global results_cache
    if not results_cache:
        print("No results cached. Execute a query first.")
        input("Press Enter to continue...")
        return

    filename = input("Enter filename to save results (e.g., results.json): ").strip()
    if not filename:
        filename = "results.json"
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_cache, f, ensure_ascii=False, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        print(f"Error saving file: {e}")
        logging.error(f"File Save Error: {e}")

    input("Press Enter to return to main menu...")


def manage_alerts_menu():
    while True:
        clear_screen()
        print("Shodan Alerts Management")
        print("========================")
        print("1. Create a new alert")
        print("2. List existing alerts")
        print("3. Delete an alert")
        print("4. Return to main menu")
        choice = input("Choose an option (1-4): ")

        if choice == "1":
            create_alert()
        elif choice == "2":
            list_alerts()
        elif choice == "3":
            delete_alert()
        elif choice == "4":
            break
        else:
            print("Invalid choice.")
            input("Press Enter to continue...")


def create_alert():
    name = input("Enter a name for the alert: ").strip()
    ip_range = input("Enter the network or IP to monitor (e.g., 1.2.3.0/24): ").strip()
    if not name or not ip_range:
        print("Invalid input. Name and IP range are required.")
        input("Press Enter to continue...")
        return
    try:
        alert = api.create_alert(name, ip_range)
        print(f"Alert created: {alert['id']}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
    input("Press Enter to continue...")


def list_alerts():
    try:
        alerts = api.alerts()
        if not alerts:
            print("No alerts found.")
        else:
            print("Existing Alerts:")
            for a in alerts:
                print(f"ID: {a['id']}, Name: {a['name']}, Filters: {a.get('filters','N/A')}")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

    input("Press Enter to continue...")


def delete_alert():
    alert_id = input("Enter the alert ID to delete: ").strip()
    if not alert_id:
        print("Invalid alert ID.")
        input("Press Enter to continue...")
        return
    try:
        api.delete_alert(alert_id)
        print("Alert deleted successfully.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")
    input("Press Enter to continue...")


def view_stats():
    q = query_builder.get_query()
    clear_screen()
    print("View Stats/Facets for Current Query")
    print("===================================")
    print("Enter a comma-separated list of facets to view.")
    print("For example: port, country, org")
    facets_input = input("Facets (e.g., port, country): ").strip()

    if not facets_input:
        print("No facets entered. Returning to main menu.")
        input("Press Enter to continue...")
        return

    facets = [f.strip() for f in facets_input.split(',') if f.strip()]
    if not facets:
        print("No valid facets found.")
        input("Press Enter to continue...")
        return

    try:
        facet_str = []
        for f in facets:
            facet_str.append(f"{f}:10")  # top 10 results per facet
        facet_query = q
        results = api.count(facet_query, facets=",".join(facet_str))

        print(f"Stats for Query: {facet_query}")
        print("="*50)
        if 'facets' in results:
            for f in facets:
                if f in results['facets']:
                    print(f"Top {f.capitalize()}s:")
                    for item in results['facets'][f]:
                        val, count = item['value'], item['count']
                        print(f"  {val}: {count}")
                    print("-"*50)
                else:
                    print(f"No data for facet '{f}'")
        else:
            print("No facet information returned.")
    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
        logging.error(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

    input("Press Enter to return to main menu...")


def exit_program():
    print("Exiting KISS. Goodbye!")
    exit()


if __name__ == "__main__":
    main_menu()
