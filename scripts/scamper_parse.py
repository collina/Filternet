#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright (C) 2013 CDA

'''

	--------------------
	Datasource
	--------------------

	scamper -p 200 -c "trace -P TCP -d 80 -g 3 -w 3 -f 2" -O warts -o outfile infile

	--------------------
	License
	--------------------
	Copyright (c) 2013, Collin Anderson
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice, this
	list of conditions and the following disclaimer.
	2. Redistributions in binary form must reproduce the above copyright notice,
	this list of conditions and the following disclaimer in the documentation
	and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	--------------------
	TODO
	--------------------
	* Add Better Logging
	* Add Attribution
'''

import argparse
import logging
import subprocess
import re
import pydot
import pygeoip

def main(args):
	global SC_ANALYSIS_DUMP_COMMAND 

	routes	= {}
	graph	= pydot.Dot(graph_type='digraph')
	mask	= [] if not args['maskip'] else args['maskip']

	for file_name in args['file_in']:
	
		command = SC_ANALYSIS_DUMP_COMMAND % file_name
		logging.info( "%s", command )
		
		for line in subprocess.check_output( command.split( " " ) ).split( '\n' ):
			line = line.rstrip().split( "\t" )
			if len(line) is 1: break
			
			routes[ (line[1], line[2]) ] = [field.split(',')[0] for field in line[6:]]
			routes[ (line[1], line[2]) ].insert(0, line[1])
			routes[ (line[1], line[2]) ].append(line[2])
			
			if args['maskhop']:
				mask += [routes[ (line[1], line[2]) ][hop] for hop in args['maskhop']]
			
			logging.info( "Hop (%s, %s): %s", line[1], line[2], routes[ (line[1], line[2]) ] )
	
	# Now I should have an awesome traceroutes dicts
	
	nodes = traceroutes_to_nodes(graph, routes, mask) # create all nodes	
	nodes = traceroutes_to_edges(graph, routes, nodes) # create all nodes	

	if args['format'] is 'dot':
		graph.write_raw(args['file_out'])
	elif args['format'] is 'svg':
		graph.write_svg(args['file_out'])
	elif args['format'] is 'png' or args['format'] is None:
		graph.write_png(args['file_out'])

	pass

def traceroutes_to_nodes(graph, routes = {}, mask = {}):
	global GEOIP_ASN, COLORS, COLOR_SE

	colors	= {}
	nodes	= {}
	cluster	= {}
	
	for trace in routes:
		if trace[0] not in nodes:			
			label = trace[0] if trace[0] not in mask else "Masked"
			nodes[ trace[0] ] = pydot.Node(trace[0], style="filled", shape="rect", width="2", fillcolor=COLOR_SE, fontcolor="#AAAAAA", fontsize = "16", label = label)

			(asn, label) = GEOIP_ASN.org_by_addr(trace[0]).split(' ', 1)
			if asn not in cluster: cluster[asn] = cluster_baz=pydot.Cluster(asn, label=label, fontsize = "18", fillcolor="azure", style="filled, rounded", shape="rect")
			cluster[asn.split()[0]].add_node(nodes[ trace[0] ])
		if trace[1] not in nodes:
			label = trace[1] if trace[1] not in mask else "Masked"
			nodes[ trace[1] ] = pydot.Node(trace[1], style="filled", shape="rect", width="2", fillcolor=COLOR_SE, fontcolor="#AAAAAA", fontsize = "16", label = label)

			(asn, label) = GEOIP_ASN.org_by_addr(trace[1]).split(' ', 1)
			if asn not in cluster: cluster[asn] = cluster_baz=pydot.Cluster(asn, label=label, fontsize = "18", fillcolor="azure", style="filled, rounded", shape="rect")
			cluster[asn.split()[0]].add_node(nodes[ trace[1] ])
		for node in routes[trace]:
			if node not in nodes and node is not 'q':
				(asn, label) = GEOIP_ASN.org_by_addr(node).split(' ', 1)
				
				if asn not in cluster: cluster[asn] = pydot.Cluster(asn, label=label, fontsize = "18", fillcolor="azure", style="filled, rounded", shape="rect")
				
				label = node if node not in mask else "Masked"
				nodes[ node ] = pydot.Node(node, style="filled, rounded", shape="rect", bordercolor="gray50", fillcolor="azure", label = label)
				
				cluster[asn.split()[0]].add_node(nodes[ node ])
	for node in sorted(nodes):
		(asn, label) = GEOIP_ASN.org_by_addr(node).split(' ', 1)
		if nodes[node].get("fillcolor") is not COLOR_SE: 
			nodes[node].set("fillcolor", COLORS[cluster.keys().index(asn) % len(COLORS)])
	for asn in cluster:
		graph.add_subgraph(cluster[asn])
	return nodes

def traceroutes_to_edges(graph, routes = {}, nodes = {}):
	
	for trace in routes:
		
		unresp_filter = {'last_id': 0, 'skipped': 0}
				
		for item in range(len(routes[trace])):
		
			if routes[trace][item] is 'q':
				unresp_filter['skipped'] = 1 if unresp_filter['skipped'] is 0 else unresp_filter['skipped'] + 1
			elif routes[trace][item] is not 'q':
			
				if item is 0:
					pass
				else: 
					label	= '* (%s)' % ( unresp_filter['skipped']) if unresp_filter['skipped'] is not 0 else ''
					line	= "#666666" if unresp_filter['skipped'] is not 0 else "#333333"
					arrow	= "empty" 	if unresp_filter['skipped'] is not 0 else "normal" 

					graph.add_edge(pydot.Edge(  nodes[routes[trace][unresp_filter['last_id']]], nodes[routes[trace][item]], arrowhead = arrow, labeltooltip = label, color = line ))
					logging.info( "Edge %s (%s, %s), skipped: %s", item, routes[trace][unresp_filter['last_id']], routes[trace][item], unresp_filter['skipped'] )
				
					unresp_filter['skipped'] = 0
					unresp_filter['last_id'] = item
				
	return graph

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		prog='Scamper to Pydot',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('file_out', default=None, help='Output file')
	parser.add_argument('file_in', nargs='*', default=None, help='Scamper Warts File to Parse')

	output = parser.add_argument_group('Output Controls')
	output.add_argument('--maskip', metavar='ip', nargs='*', help='Mask IPs')
	output.add_argument('--maskhop', metavar='hop', type=int, nargs='*', help='Mask Hops')
	output.add_argument('--format', metavar='format', choices=['dot','png','svg'], default='png', help='Output Format')

	GEOIP_ASN	= pygeoip.GeoIP('./GeoIPASNum.dat')
	SC_ANALYSIS_DUMP_COMMAND = "sc_analysis_dump -C -l -c -t -r %s"
	COLORS		= ["#a6cee3", "#1f78b4","#b2df8a","#33a02c","#fb9a99","#e31a1c","#fdbf6f","#ff7f00","#cab2d6","#6a3d9a","#ffff99","#b15928"]
	COLOR_SE	= "#333333"
	logging.basicConfig(level=logging.WARN)
	
	args = vars(parser.parse_args())
	
	if args['file_out'] is None or not args['file_out']:
		parser.print_help()
	
	main(args)
