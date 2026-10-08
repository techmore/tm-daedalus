"""Deterministic diagram coordinates for already scoped topology evidence."""
from collections import deque


def layout_network(network: dict) -> dict:
    nodes = network.get("nodes") or []
    links = network.get("links") or []
    if network.get("status") != "complete" or not nodes:
        return {"status": "empty" if network.get("status") == "complete" else "unavailable", "nodes": [], "links": []}
    # Diagram previews share the existing 50-node/100-link dashboard bounds.
    if len(nodes) > 50 or len(links) > 100:
        return {"status": "too_large", "nodes": [], "links": []}
    by_id = {node["device_serial"]: node for node in nodes}
    adjacency = {key: set() for key in by_id}
    for link in links:
        a, b = link["device_serials"]
        adjacency[a].add(b); adjacency[b].add(a)
    order = lambda key: (by_id[key]["reported_root"] is not True, by_id[key]["name"].casefold(), key)
    remaining = set(by_id)
    layers = []
    while remaining:
        anchor = min(remaining, key=order)
        queue = deque([(anchor, 0)]); distances = {}
        while queue:
            key, depth = queue.popleft()
            if key in distances:
                continue
            distances[key] = depth
            queue.extend((other, depth + 1) for other in sorted(adjacency[key], key=order) if other not in distances)
        remaining -= distances.keys()
        for depth in range(max(distances.values()) + 1):
            layer = sorted((key for key, value in distances.items() if value == depth), key=order)
            layers.extend(layer[start:start + 5] for start in range(0, len(layer), 5))
    positioned = []
    index = {node["device_serial"]: i + 1 for i, node in enumerate(nodes)}
    for y, layer in enumerate(layers):
        offset = (1000 - len(layer) * 196) / 2
        for x, key in enumerate(layer):
            positioned.append({**by_id[key], "number": index[key], "x": offset + x * 196 + 8,
                               "y": 25 + y * 105, "width": 180, "height": 70})
    return {"status": "available", "width": 1000, "height": len(layers) * 105 + 25,
            "nodes": positioned, "links": links,
            "scope": "Lines show saved undirected relationships. Rows use graph distance from an API-root flag or a deterministic layout anchor; they do not establish upstream/downstream traffic, physical placement or Internet connectivity. Device numbers match the key below."}


def diagram_sheets(diagram: dict) -> list[dict]:
    """Eight layout rows per sheet, with explicit references for crossing links."""
    if diagram.get("status") != "available":
        return []
    by_id = {node["device_serial"]: node for node in diagram["nodes"]}
    bands = sorted({int(node["y"] // 840) for node in by_id.values()})
    sheet_for = {node["device_serial"]: bands.index(int(node["y"] // 840)) + 1 for node in by_id.values()}
    result = []
    for index, band in enumerate(bands, 1):
        nodes = [{**node, "y": node["y"] - band * 840} for node in by_id.values() if sheet_for[node["device_serial"]] == index]
        ids = {node["device_serial"] for node in nodes}
        links, references = [], []
        for link in diagram["links"]:
            a, b = link["device_serials"]
            if a in ids and b in ids:
                links.append(link)
            elif a in ids or b in ids:
                local, other = (a, b) if a in ids else (b, a)
                references.append({"local_number": by_id[local]["number"], "other_number": by_id[other]["number"],
                    "other_sheet": sheet_for[other], "link_count": link["link_count"]})
        result.append({"sheet": index, "sheet_count": len(bands), "nodes": nodes, "links": links,
            "cross_sheet_links": references, "width": diagram["width"],
            "height": max(node["y"] + node["height"] for node in nodes) + 25})
    return result
