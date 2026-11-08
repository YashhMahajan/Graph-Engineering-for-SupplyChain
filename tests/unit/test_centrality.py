"""Articulation points and bridges (Hopcroft-Tarjan): answers checkable by hand."""

from __future__ import annotations

import numpy as np

from scgraph.centrality import articulation_points_and_bridges


def csr(n: int, edges: list[tuple[int, int]]):
    src = np.array([a for a, _ in edges], dtype=np.int64)
    dst = np.array([b for _, b in edges], dtype=np.int32)
    order = np.argsort(src, kind="stable")
    indptr = np.zeros(n + 1, np.int64)
    np.cumsum(np.bincount(src, minlength=n), out=indptr[1:])
    return indptr, dst[order]


def run(n: int, edges: list[tuple[int, int]]):
    is_art, bridges, ncomp = articulation_points_and_bridges(*csr(n, edges), n)
    return (
        {i for i in range(n) if is_art[i]},
        {frozenset(b) for b in bridges},
        ncomp,
    )


def pairs(*edges: tuple[int, int]) -> set[frozenset[int]]:
    return {frozenset(e) for e in edges}


def test_a_path_cuts_at_every_inner_node_and_every_edge_is_a_bridge() -> None:
    art, bridges, ncomp = run(4, [(0, 1), (1, 2), (2, 3)])
    assert art == {1, 2} and bridges == pairs((0, 1), (1, 2), (2, 3)) and ncomp == 1


def test_a_cycle_has_no_cut_node_and_no_bridge() -> None:
    art, bridges, ncomp = run(4, [(0, 1), (1, 2), (2, 3), (3, 0)])
    assert art == set() and bridges == set() and ncomp == 1


def test_a_star_cuts_at_its_centre() -> None:
    art, bridges, _ = run(4, [(0, 1), (0, 2), (0, 3)])
    assert art == {0} and bridges == pairs((0, 1), (0, 2), (0, 3))


def test_two_triangles_sharing_a_node_cut_there_but_have_no_bridge() -> None:
    edges = [(0, 1), (1, 2), (2, 0), (2, 3), (3, 4), (4, 2)]  # a bowtie around node 2
    art, bridges, _ = run(5, edges)
    assert art == {2} and bridges == set()


def test_two_triangles_joined_by_an_edge_have_two_cut_nodes_and_one_bridge() -> None:
    edges = [(0, 1), (1, 2), (2, 0), (3, 4), (4, 5), (5, 3), (2, 3)]
    art, bridges, _ = run(6, edges)
    assert art == {2, 3} and bridges == pairs((2, 3))


def test_direction_is_ignored_and_components_are_counted() -> None:
    # edges are given one way only; the graph is the undirected path 0-1-2 plus the edge 3-4
    art, bridges, ncomp = run(5, [(0, 1), (2, 1), (3, 4)])
    assert art == {1} and bridges == pairs((0, 1), (1, 2), (3, 4)) and ncomp == 2


def test_a_graph_with_no_edges_has_nothing_to_report() -> None:
    art, bridges, ncomp = run(3, [])
    assert art == set() and bridges == set() and ncomp == 3
