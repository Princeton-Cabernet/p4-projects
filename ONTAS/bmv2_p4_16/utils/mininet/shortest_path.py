class ShortestPath:

    def __init__(self, edges=[]):
        self.neighbors = {}
        for edge in edges:
            self.addEdge(*edge)

    def addEdge(self, a, b):
        if a not in self.neighbors: self.neighbors[a] = []
        if b not in self.neighbors[a]: self.neighbors[a].append(b)

        if b not in self.neighbors: self.neighbors[b] = []
        if a not in self.neighbors[b]: self.neighbors[b].append(a)

    def get(self, a, b, exclude=lambda node: False):
        # Shortest path from a to b
        return self._recPath(a, b, [], exclude)

    def _recPath(self, a, b, visited, exclude):
        if a == b: return [a]
        new_visited = visited + [a]
        paths = []
        for neighbor in self.neighbors[a]:
            if neighbor in new_visited: continue
            if exclude(neighbor) and neighbor != b: continue
            path = self._recPath(neighbor, b, new_visited, exclude)
            if path: paths.append(path)

        paths.sort(key=len)
        return [a] + paths[0] if len(paths) else None

if __name__ == '__main__':

    edges = [
            (1, 2),
            (1, 3),
            (1, 5),
            (2, 4),
            (3, 4),
            (3, 5),
            (3, 6),
            (4, 6),
            (5, 6),
            (7, 8)

    ]
    sp = ShortestPath(edges)

    assert sp.get(1, 1) == [1]
    assert sp.get(2, 2) == [2]

    assert sp.get(1, 2) == [1, 2]
    assert sp.get(2, 1) == [2, 1]

    assert sp.get(1, 3) == [1, 3]
    assert sp.get(3, 1) == [3, 1]

    assert sp.get(4, 6) == [4, 6]
    assert sp.get(6, 4) == [6, 4]

    assert sp.get(2, 6) == [2, 4, 6]
    assert sp.get(6, 2) == [6, 4, 2]

    assert sp.get(1, 6) in [[1, 3, 6], [1, 5, 6]]
    assert sp.get(6, 1) in [[6, 3, 1], [6, 5, 1]]

    assert sp.get(2, 5) == [2, 1, 5]
    assert sp.get(5, 2) == [5, 1, 2]

    assert sp.get(4, 5) in [[4, 3, 5], [4, 6, 5]]
    assert sp.get(5, 4) in [[5, 3, 4], [6, 6, 4]]

    assert sp.get(7, 8) == [7, 8]
    assert sp.get(8, 7) == [8, 7]

    assert sp.get(1, 7) == None
    assert sp.get(7, 2) == None

