#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright (C) 2013 CDA

'''

	--------------------
	About
	--------------------
	Networking monitoring firms have pretty tools to collect and
	parse data on routes and performance, why shouldn't we?
	
	Author: Collin Anderson
	Email: collin@averysmallbird.com
	Version: 1.0-pre
	--------------------
	Datasource
	--------------------

	We use scamper for preparation, it's pretty cool and available in repos.
	
	e.g. scamper -p 200 -c "trace -P TCP -d 80 -g 3 -w 3 -f 2" -O warts -o outfile infile

	--------------------
	License (BSD 2-Clause, Thanks for Caring)
	--------------------
	Copyright (c) 2013, Collin Anderson
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or
	without modification, are permitted provided that the following
	conditions are met:
	
	(1) Redistributions of source code must retain the above copyright
	notice, this list of conditions and the following disclaimer.
	
	(2) Redistributions in binary form must reproduce the above copyright
	notice, this list of conditions and the following disclaimer in
	the documentation and/or other materials provided with the
	distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
	CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
	CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
	LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
	USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
	AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
	LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
	ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
	

	--------------------
	TODO
	--------------------
	* Add Better Logging
	* Add Attribution
	* Tighter scamper integration?!
	
'''

import argparse
import logging
import subprocess
import re
import pydot
import pygeoip
import networkx
from matplotlib import pyplot

def main(args):
    global SC_ANALYSIS_DUMP_COMMAND 

    routes	= {}
    graph	= pydot.Dot(graph_type='digraph', rankdir = 'LR', ranksep = '2', nodesep = '.1', model = "circuit")
    mask	= [] if not args['maskip'] else args['maskip']

    for file_name in args['file_in']:

        command = SC_ANALYSIS_DUMP_COMMAND % file_name
        logging.info( "%s", command )
        sc_analysis = subprocess.Popen(command.split( " " ), stdout=subprocess.PIPE, close_fds=True).communicate()[0]
        
        for line in sc_analysis.split( '\n' ):
            line = line.rstrip().split( "\t" )
            if len(line) is 1: continue
            if args['responding'] and line[3] is 'G': continue
            
            routes[ (line[1], line[2]) ] = [field.split(',')[0] for field in line[6:]]
            routes[ (line[1], line[2]) ].insert(0, line[1])
            routes[ (line[1], line[2]) ].append(line[2])
            
            if args['maskhop']:
                mask += [routes[ (line[1], line[2]) ][hop] for hop in args['maskhop']]
        
            logging.info( "Hop (%s, %s): %s", line[1], line[2], routes[ (line[1], line[2]) ] )

    # Now I should have an awesome traceroutes dicts

    nodes = traceroutes_to_nodes(graph, routes, mask, minimal = args['minimal']) # create all nodes
    nodes = traceroutes_to_edges(graph, routes, mask, nodes, minimal = args['minimal']) # create all nodes
                
    if args['format'] == 'dot' or args['format'] == 'raw':
        graph.write_raw(args['file_out'])
    elif args['format'] == 'svg':
        graph.write_svg(args['file_out'])
    elif args['format'] == 'png' or args['format'] is None:
        graph.write_png(args['file_out'])

    return True # superstition

def traceroutes_to_nodes(graph, routes = {}, mask = {}, minimal = False):
    global GEOIP_ASN, COLORS, COLOR_SE

    nodes	= {}
    cluster	= {}
    mask_asn = {}
    membership = []
    
    if minimal is False:
        node_style = {
            'style' : "filled, rounded",
            'shape' : "rect",
            'nodesep' : 'auto',
            'width' : "auto",
            'width_end' : '2'
        }
    else:
        node_style = {
            'style' : "filled, rounded",
            'nodesep' : 'auto',
            'shape' : "point",
            'width' : "auto",
            'width_end' : '.1'
        }

    for trace in routes:
        for node in routes[trace]:
            if node not in nodes and node is not 'q':

                lookup = GEOIP_ASN.org_by_addr(node)
                
                if lookup is not None:
                    if len(lookup.split(' ', 1)) > 1:
                        (asn, label) = lookup.split(' ', 1)
                    elif len(lookup.split(' ', 1)) is 1:
                        (asn, label) = (lookup, '')
                    else:
                        (asn, label) = ('Error', 'Error')
                else:
                    (asn, label) = ('Private', 'Private')

                if asn not in cluster:
                    cluster[asn] = pydot.Cluster(asn, label=re.escape(label), fontsize = "18", fillcolor="azure", style="filled, rounded", shape="rect")

                label = node if node not in mask else "Masked"
                name = node if node not in mask else "masked-" + str(mask.index(node))
            
                nodes[ name ] = pydot.Node(name, style=node_style['style'], nodesep=node_style['nodesep'], width=node_style['width'], shape= node_style['shape'], bordercolor="gray50", fillcolor="azure", fontcolor = "black", fontsize = "14", label = label)
                if node is trace[0] or node is trace[-1]:
                    nodes[ name ].set("fillcolor", COLOR_SE)
                    nodes[ name ].set("style", "filled")
                    nodes[ name ].set("fontcolor", "#AAAAAA")
                    nodes[ name ].set("fontsize", "16")
                    nodes[ name ].set("width", node_style['width_end'])

                cluster[asn].add_node(nodes[ name ])
    for asn in cluster:
        for node in cluster[asn].get_nodes():
            if node.get("fillcolor") is not COLOR_SE: 
                node.set("fillcolor", COLORS[cluster.keys().index(asn) % len(COLORS)])
        #graph.add_subgraph(cluster[asn])

    more_structured(graph, cluster, routes)
    return nodes

def traceroutes_to_edges(graph, routes = {}, mask = {}, nodes = {}, minimal = False):
    global GEOIP_ASN, COLORS, COLOR_SE

    if minimal is False:
        edge_style = {
                'arrowhead' : "arrow",
                'arrowsize' : "auto",
            }
    else:
        edge_style = {
                'arrowhead' : "arrow",
                'arrowsize' : ".1",
            }
    for trace in routes:
        unresp_filter = {'last_id': 0, 'skipped': 0}
        for item in range(len(routes[trace])):
            if routes[trace][item] is 'q':  unresp_filter['skipped'] = 1 if unresp_filter['skipped'] is 0 else unresp_filter['skipped'] + 1
            elif routes[trace][item] is not 'q':
                if item is 0: pass
                else:
                    label	= '* (%s)' % ( unresp_filter['skipped']) if unresp_filter['skipped'] is not 0 else ''
                    line	= "#666666" if unresp_filter['skipped'] is not 0 else "#333333"
                    arrow	= "empty" 	if unresp_filter['skipped'] is not 0 else "normal" 

                    name_1 = routes[trace][unresp_filter['last_id']] if routes[trace][unresp_filter['last_id']] not in mask else "masked-" + str(mask.index( routes[trace][unresp_filter['last_id']]))
                    name_2 = routes[trace][item] if routes[trace][item] not in mask else "masked-" + str(mask.index(routes[trace][item]))
                    
                    constraint = "true" if GEOIP_ASN.org_by_addr(routes[trace][unresp_filter['last_id']]) is not GEOIP_ASN.org_by_addr(routes[trace][item]) else "false"
                    
                    edge = pydot.Edge(  nodes[name_1], nodes[name_2], arrowhead = edge_style['arrowhead'], arrowsize = edge_style['arrowsize'], labeltooltip = label, color = line, constraint = constraint, penwidth = "2")
                    graph.add_edge(edge)
                    logging.info( "Edge %s (%s, %s), skipped: %s", item, routes[trace][unresp_filter['last_id']], routes[trace][item], unresp_filter['skipped'] )

                    unresp_filter['skipped'] = 0
                    unresp_filter['last_id'] = item

    return graph

def more_structured(graph, cluster, routes, target_country = "IR"):
    '''
        Five ranks: (start) (in between) (pre gw, nat) (gw) (post gw) (end)
    '''
    global GEOIP_ASN, GEOIP_CC

    origins = [GEOIP_ASN.org_by_addr(route[0]).split()[0] for route in routes]
    ends = [GEOIP_ASN.org_by_addr(route[-1]).split()[0] for route in routes]
    gateways = ['AS12880', 'Private']

    domestic, international = [], []
    for session, route in routes.items():
        for node in route:
            if node is 'q': continue
            asn = GEOIP_ASN.org_by_addr(node)
            if asn is None: continue
            
            cc = GEOIP_CC.country_code_by_addr(node)
            if cc is target_country:
                domestic.append(asn.split()[0])
            # if transition international -> domestic: gw += [node]
            else:
                international.append(asn.split()[0])

    
    region = {'origin': None, 'international': None, 'gateway': None, 'domestic': None, 'end': None}
    prlabel = None

    for rlabel in region:
        region[rlabel]=pydot.Cluster(rlabel,label=None, style="invis", rank="min")
        region[rlabel].add_node(pydot.Node('node_'+rlabel, style="invis"))
        if prlabel is not None: graph.add_edge(pydot.Edge('node_' + prlabel,'node_' + rlabel, style="invis", constraint = "false"))
        graph.add_subgraph(region[rlabel])
        prlabel = rlabel

    
    for asn in cluster:
        if asn in origins:
            cluster[asn].set("fillcolor", "#B8AA8F")
            region['origin'].add_subgraph(cluster[asn])
        elif asn in gateways:
            cluster[asn].set("fillcolor", "#B88F90")
            region['gateway'].add_subgraph(cluster[asn])
        elif asn in ends:
            cluster[asn].set("fillcolor", "#7EA2A1")
            region['end'].add_subgraph(cluster[asn])
        elif asn in domestic:
            cluster[asn].set("fillcolor", "#7EA2A1")
            region['domestic'].add_subgraph(cluster[asn])
        elif asn in international:
            cluster[asn].set("fillcolor", "#B8AA8F")
            region['international'].add_subgraph(cluster[asn])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Scamper to Pydot',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('file_out', default=None, help='Output file')
    parser.add_argument('file_in', nargs='+', default=None, help='Scamper Warts File to Parse')

    output = parser.add_argument_group('Output Controls')
    output.add_argument('--maskip', metavar='ip', nargs='+', help='Mask IPs in Graph')
    output.add_argument('--maskhop', metavar='hop', type=int, nargs='+', help='Mask Hops in Graph')
    output.add_argument('--skiphop', metavar='hop', type=int, nargs='+', help='Skip Hops in Graph')
    output.add_argument('--format', metavar='format', choices=['dot','png','svg'], default='png', help='Output Format')
    output.add_argument('--responding', action='store_true', help='Skip non-responding nodes')
    output.add_argument('--minimal', action='store_true', help='Minimal Node Representation')
    
    GEOIP_ASN	= pygeoip.GeoIP('./GeoIPASNum.dat')
    GEOIP_CC      = pygeoip.GeoIP('./GeoLiteCity.dat')

    SC_ANALYSIS_DUMP_COMMAND = "sc_analysis_dump -C -l -c -t -r %s"
    COLORS		= ["#a6cee3", "#1f78b4","#b2df8a","#33a02c","#fb9a99","#e31a1c","#fdbf6f","#ff7f00","#cab2d6","#6a3d9a","#ffff99","#b15928"]
    COLOR_SE	= "#333333"
    logging.basicConfig(level=logging.WARN)

    args = vars(parser.parse_args())

    if args['file_out'] is None or not args['file_out']:
        parser.print_help()

    main(args)
