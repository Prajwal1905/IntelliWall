import networkx as nx

G = nx.Graph()


def update_graph(source, risk):
    SERVER_NODE = "Firewall"

    if not G.has_node(source):
        G.add_node(source)

    if not G.has_node(SERVER_NODE):
        G.add_node(SERVER_NODE)

    G.add_edge(source, SERVER_NODE, weight=risk)

    return nx.node_link_data(G)


def get_suspicious_nodes():
    suspicious = []

    for node in G.nodes():
        neighbors = list(G.neighbors(node))

        if not neighbors:
            continue

        connections = len(neighbors)
        total_risk = sum(G[node][nbr].get("weight", 0) for nbr in neighbors)

        if connections >= 3 or total_risk > 150:
            suspicious.append(node)

    return suspicious