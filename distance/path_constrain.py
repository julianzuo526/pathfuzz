#!/usr/bin/env python3
"""
Compute the set of functions that should be instrumented for directed fuzzing.
Given a call graph and a target function list, identify:
1. All functions on the call path from entry to targets.
2. Functions that are called before each target in the same caller.
3. Recursively dependent functions.
4. (Optional) Intra-function callees via basic block analysis.

Usage:
    python3 instrumentation_analyzer.py temp_dir

Inputs (in temp_dir):
    - call_graph.txt      : Function call graph
    - target_funcs.txt    : List of target functions (one per line)
    - entry_func.txt      : File containing a single line with the entry function name

Output:
    - instrumented_funcs.txt : Written to the same temp_dir
"""

import sys
from pathlib import Path
from collections import defaultdict, deque


def parse_call_graph_file(file_path):
    call_graph = defaultdict(list)
    call_sites = defaultdict(list)

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or ',' not in line or ':' not in line:
                continue
            try:
                caller, callee_part = line.split(',')
                callee, lineno = callee_part.split(':')
                lineno = int(lineno)
            except ValueError:
                print(f"Skipping malformed line: {line}")
                continue

            call_graph[caller].append(callee)
            call_sites[caller].append((callee, lineno))

    return dict(call_graph), dict(call_sites)


def get_call_path(call_graph, start, target):
    path = []
    visited = set()

    def dfs(node, current_path):
        if node in visited:
            return False
        visited.add(node)
        current_path.append(node)
        if node == target:
            path.extend(current_path)
            return True
        for callee in call_graph.get(node, []):
            if dfs(callee, current_path):
                return True
        current_path.pop()
        return False

    dfs(start, [])
    return path


def get_preceding_dependent_funcs(call_sites, target_func):
    dependent_funcs = set()
    for caller, callee_infos in call_sites.items():
        target_lines = [line for callee, line in callee_infos if callee == target_func]
        if not target_lines:
            continue
        for callee, line in callee_infos:
            if any(line < tgt_line for tgt_line in target_lines) and callee != target_func:
                dependent_funcs.add(callee)
    return dependent_funcs


def get_recursive_dependencies(call_graph, initial_funcs):
    all_deps = set(initial_funcs)
    queue = deque(initial_funcs)
    while queue:
        func = queue.popleft()
        for callee in call_graph.get(func, []):
            if callee not in all_deps:
                all_deps.add(callee)
                queue.append(callee)
    return all_deps


def expand_by_internal_calls(func_list, bb_calls):
    expanded = set(func_list)
    queue = deque(func_list)
    while queue:
        func = queue.popleft()
        for bb in bb_calls.get(func, []):
            for callee in bb:
                if callee not in expanded:
                    expanded.add(callee)
                    queue.append(callee)
    return expanded


def read_target_func_file(target_file):
    with open(target_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]


def read_entry_func(entry_file):
    with open(entry_file, 'r', encoding='utf-8') as f:
        return f.readline().strip()


def compute_instrumentation_set(call_graph, call_sites, bb_calls, entry_func, target_funcs):
    instrumentation_funcs = set()
    for target_func in target_funcs:
        forward_path = get_call_path(call_graph, entry_func, target_func)
        direct_deps = get_preceding_dependent_funcs(call_sites, target_func)
        recursive_deps = get_recursive_dependencies(call_graph, direct_deps)
        bb_expanded = expand_by_internal_calls(recursive_deps, bb_calls)
        combined = set(forward_path) | recursive_deps | bb_expanded
        instrumentation_funcs.update(combined)
    return instrumentation_funcs


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 path_constrain.py temp_dir")
        sys.exit(1)

    temp_dir = Path(sys.argv[1])
    call_graph_path = temp_dir / "call_graph.txt"
    target_func_file = temp_dir / "target_funcs.txt"
    entry_func_file = temp_dir / "entry_func.txt"
    output_file = temp_dir / "instrumented_funcs.txt"

    entry_func = read_entry_func(entry_func_file)

    call_graph, call_sites = parse_call_graph_file(call_graph_path)
    target_funcs = read_target_func_file(target_func_file)

    # Optional: fill in basic block calls if needed
    bb_calls = {}

    result = compute_instrumentation_set(call_graph, call_sites, bb_calls, entry_func, target_funcs)

    with output_file.open('w', encoding='utf-8') as f:
        for func in sorted(result):
            f.write(func + '\n')

    print(f"Instrumentation function list written to: {output_file}")


if __name__ == '__main__':
    main()
