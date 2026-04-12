import networkx as nx

G = nx.Graph()

def update_graph(source, risk):
    SERVER_NODE = "Firewall"

    # add nodes
    if not G.has_node(source):
        G.add_node(source)

    if not G.has_node(SERVER_NODE):
        G.add_node(SERVER_NODE)

    # connect source to firewall
    G.add_edge(source, SERVER_NODE, weight=risk)

    return nx.node_link_data(G)