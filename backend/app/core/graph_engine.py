import networkx as nx

G = nx.Graph()

def update_graph(source, risk):
    if not G.has_node(source):
        G.add_node(source)

    SERVER_NODE="Firewall"
    target=SERVER_NODE
    G.add_edge(source, target, weight=risk)

    return nx.node_link_data(G)


def get_suspicious_nodes():
    suspicious = []
    
    for node in G.nodes():
        connections = len(list(G.neighbors(node)))
        total_risk = sum([G[node][nbr]['weight'] for nbr in G.neighbors(node)])

        if connections >= 3 or total_risk > 150:
            suspicious.append(node)
    
    return suspicious