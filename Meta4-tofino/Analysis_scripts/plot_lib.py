#################################################
# (c) Copyright 2014 Hyojoon Kim
# All Rights Reserved 
# 
# email: deepwater82@gmail.com
#################################################

import operator
import string
import pickle
import sys
import re
import time
import os
import sqlite3 as db
import shlex, subprocess
import hashlib
import xml.etree.ElementTree as ET
from multiprocessing import Process
from multiprocessing import Pool
from collections import namedtuple
from datetime import datetime
import tarfile
import matplotlib as mpl
#mpl.use('PS')
#mpl.use('pdf')
mpl.use('AGG')
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
from numpy.random import normal
import numpy as np
from matplotlib.patches import ConnectionPatch
import struct
from socket import *


#mpl.rc('text', usetex=True)
mpl.rc('font', **{'family':'serif', 'sans-serif': ['Times'], 'size': 9})
mpl.rc('figure', figsize=(5.33, 4.06))
#mpl.rc('figure', figsize=(5.33, 2.06))
#mpl.rc('figure', figsize=(3.33, 2.06))
mpl.rc('axes', linewidth=0.5)
mpl.rc('patch', linewidth=0.5)
mpl.rc('lines', linewidth=0.5)
mpl.rc('grid', linewidth=0.25)


def plot_avg_bar(data_llist, rate_list, output_dir, filename, title):
        
    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
#    mpl.rc('figure', figsize=(4.33, 2.06))
    ax.set_yscale('log')

    colors = ['r','k','g','c','y','m','b']
    hatch = ['-', '+', 'x', '\\', '*', 'o', 'O', '.']
#    colors = ['r-+','k-*','g-^','c-h','r-.']
    pl = []
  #    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')
 
    xlabels = rate_list
    majorind = np.arange(len(data_llist[0]),step=1)
    plt.xticks(majorind,xlabels,fontsize=8)
    width = 9.0/len(data_llist[0])/len(data_llist[0])*1.5

#    ax.boxplot(data,sym='')
    plt.ylim(1,100000)
    plt.xlim([majorind[0] - width*5, majorind[-1] + width*5])

#    tick_space = 1.5
#    ax = plt.axes()
#    ax.xaxis.set_major_locator(MultipleLocator(tick_space))

#    nflows_median = []
#    nflows_maxerr = []
#    nflows_minerr = []
#    instances_list = y_map.keys()
#    nflows_len = len(y_map[instances_list[0]])
#
#    for i in range(nflows_len):
#        this_flow_list = []
#        for idx2,y in enumerate(y_map):
#            this_flow_list.append(y_map[y][i])
#        nflows_median.append(np.median(this_flow_list))
#        nflows_maxerr.append(np.max(this_flow_list) - np.median(this_flow_list))
#        nflows_minerr.append(np.median(this_flow_list) - np.min(this_flow_list))
#
#    pl.append(plt.errorbar(x_ax, nflows_median, yerr=[nflows_minerr, nflows_maxerr], fmt='r-o',markersize=1.5))
#    weights = []
#    weights.append = np.ones_like(x)
#    n, bins, patches = plt.hist( data_llist, 10, weights=[1,1,1,1,1], histtype='bar')
#    n, bins, patches = plt.hist( data_llist, histtype='bar')
 
    length = len(data_llist)

    if length%2==0:
        for idx,d in enumerate(data_llist):
            if idx<length/2:
                pl.append(ax.bar(majorind-(width)*(length/2-idx), d,width=width,
                                 log=True,color=colors[idx],hatch=hatch[idx]))
            else:
                pl.append(ax.bar(majorind+(width)*((idx)-length/2), d,width=width,
                                 log=True,color=colors[idx],hatch=hatch[idx]))
    else:
        print(data_llist,'\n')
        for idx,d in enumerate(data_llist):
            if idx<length/2:
                pl.append(ax.bar(majorind-width/2-(width)*(length/2-idx), d,width=width,log=True,
                                 color=colors[idx],hatch=hatch[idx]))
            else:
                pl.append(ax.bar(majorind-width/2+(width)*(idx-length/2), d,width=width,log=True,
                                 color=colors[idx],hatch=hatch[idx]))

    l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0],pl[4][0],pl[5][0],pl[6][0]],
                   ['Arista','BrocadeMLX','Cisco3650','Cisco3850-inband','Cisco3850','HP-J9307A', 'HP-J9538A'], bbox_to_anchor=(0.5, 1.33),
                   loc='upper center',ncol=6, fancybox=True, shadow=False,
                   prop={'size':5.0})    


    ff = plt.gcf()
    ff.subplots_adjust(top=0.80)
    ff.subplots_adjust(bottom=0.20)
#    ff.subplots_adjust(left=0.22)
    ff.subplots_adjust(right=0.98)
    plt.title(title)
    plt.xlabel('Flow installation Rate (Num. of rules/second)')
    plt.ylabel('Delay (ms)', rotation=90)
 

    plt.savefig(output_dir + str(filename), dpi=700)
    plt.close()


def plot_boxplot(data, rate_list, output_dir, filename, title):
    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    colors = ['r-+','k-*','g-^','c-h','r-.']
    pl = []
    #  ax.set_yscale('log')
  #    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')
 
    xlabels = rate_list
    majorind = np.arange(len(data),step=1)
    plt.xticks(majorind,xlabels)

    ax.boxplot(data,sym='')
    plt.ylim(0,500)

#    nflows_median = []
#    nflows_maxerr = []
#    nflows_minerr = []
#    instances_list = y_map.keys()
#    nflows_len = len(y_map[instances_list[0]])
#
#    for i in range(nflows_len):
#        this_flow_list = []
#        for idx2,y in enumerate(y_map):
#            this_flow_list.append(y_map[y][i])
#        nflows_median.append(np.median(this_flow_list))
#        nflows_maxerr.append(np.max(this_flow_list) - np.median(this_flow_list))
#        nflows_minerr.append(np.median(this_flow_list) - np.min(this_flow_list))
#
#    pl.append(plt.errorbar(x_ax, nflows_median, yerr=[nflows_minerr, nflows_maxerr], fmt='r-o',markersize=1.5))

  
    ff = plt.gcf()
    ff.subplots_adjust(bottom=0.20)
    ff.subplots_adjust(left=0.22)
    plt.title(title)
    plt.xlabel('Flow installation Rate (Num. of rules/second)')
    plt.ylabel('Delay (ms)', rotation=90)
    
    plt.savefig(output_dir + str(filename), dpi=700)
    plt.close()


def plot_distribution(x_ax, y_map, output_dir, filename, title):
    fig = plt.figure(dpi=700)
    ax = fig.add_subplot(111)
    colors = ['r-+','k-*','g-^','c-h','r-.']
    pl = []
    #  ax.set_yscale('log')
  #    ax.xaxis.grid(True, which='major')
    ax.yaxis.grid(True, which='major')
  
    nflows_median = []
    nflows_maxerr = []
    nflows_minerr = []
    instances_list = y_map.keys()
    nflows_len = len(y_map[instances_list[0]])

    for i in range(nflows_len):
        this_flow_list = []
        for idx2,y in enumerate(y_map):
            this_flow_list.append(y_map[y][i])
        nflows_median.append(np.median(this_flow_list))
        nflows_maxerr.append(np.max(this_flow_list) - np.median(this_flow_list))
        nflows_minerr.append(np.median(this_flow_list) - np.min(this_flow_list))

    pl.append(plt.errorbar(x_ax, nflows_median, yerr=[nflows_minerr, nflows_maxerr], fmt='r-o',markersize=1.5))

  
    ff = plt.gcf()
    ff.subplots_adjust(bottom=0.20)
    ff.subplots_adjust(left=0.15)
    plt.title(title)
    plt.xlabel('Number of flows')
    plt.ylabel('Delay (seconds)', rotation=90)
    
    plt.savefig(output_dir + str(filename), dpi=700)


def plot_singleline(x_ax, y_ax, output_dir, filename, xlabel_name, ylabel_name, title, xlogscale=False, ylogscale=False, pointdot=False, ccdf=False):

  fig = plt.figure(dpi=700)
  ax = fig.add_subplot(111)
  if pointdot:
    colors = ['r-*','k-+','g-^','c-h','r-.']
  else:
    colors = ['r-','k-','g-','c-','r-']

  pl = []

  if xlogscale:
    ax.set_xscale('log')
  if ylogscale:
    ax.set_yscale('log')

  ax.xaxis.grid(True, which='major')
  ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))

  if ccdf:
    pl.append( plt.plot(x_ax, 1-np.array(y_ax), '%s' %(colors[0]), label="", markersize=2) )
  else:
    pl.append( plt.plot(x_ax, y_ax, '%s' %(colors[0]), label="", markersize=2) )
  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
#  plt.xlim(0,150)

  ff = plt.gcf()
  ff.subplots_adjust(bottom=0.20)
  ff.subplots_adjust(left=0.15)
  plt.title(title)
  plt.xlabel(xlabel_name)
  plt.ylabel(ylabel_name, rotation=90)

#  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['One Task','50 Tasks','100 Tasks','150 Tasks'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
  
  plt.savefig(output_dir + str(filename), dpi=700)



def plot_multiline(x_ax, y_map, output_dir, filename, title):

  fig = plt.figure(dpi=700)
  ax = fig.add_subplot(111)
  colors = ['r-+','k-*','g-^','c-h','r-.']
  pl = []
  #  ax.set_yscale('log')
#    ax.xaxis.grid(True, which='major')
  ax.yaxis.grid(True, which='major')

  #  ind = np.arange(len(ya))


  for idx,y in enumerate(y_map):
    y_ax = y_map[y]
    cidx = idx%len(colors)
    pl.append( plt.plot(x_ax, y_ax, '%s' %(colors[cidx]), label="") )
  
  # xlabels = ['0', '10', '20', '30', '40', '50', '60']
  #  majorind = np.arange(len(ya),step=99)
  #  plt.xticks(majorind,xlabels)
 
  if filename.find('add_delay') != -1:
       pass
#      plt.ylim(0,20)
#      plt.ylim(0,100)

  elif filename.find('mod_delay') != -1:
      pass
#      plt.ylim(0,5)
#      plt.ylim(0,200)

#  plt.xlim(0,150)

  ff = plt.gcf()
  ff.subplots_adjust(bottom=0.20)
  ff.subplots_adjust(left=0.15)
  plt.title(title)
  plt.xlabel('Number of flows')
  plt.ylabel('Delay (seconds)', rotation=90)

#  l = plt.legend([pl[0][0],pl[1][0],pl[2][0],pl[3][0]], ['One Task','50 Tasks','100 Tasks','150 Tasks'], bbox_to_anchor=(0.5, 1.1), loc='upper center',ncol=2, fancybox=True, shadow=False, prop={'size':7.0})    
  
  plt.savefig(output_dir + str(filename), dpi=700)


def get_cdf2(arr):
  '''
      Fn to get CDF of an array
      Input: unsorted array with values
      Output: 2 arrays - x and y axes values
  '''
  sarr = np.sort(arr)
  l = len(sarr)
  x = []
  y = []
  for i in range(0,l):
    x.append(sarr[i])
    y.append(float(i+1)/l)

  return x,y

def get_cdf2(arr):
  '''
      Fn to get CDF of an array
      Input: unsorted array with values
      Output: 2 arrays - x and y axes values
  '''
  sarr = np.sort(arr)
  l = len(sarr)
  x = []
  y = []
  for i in range(0,l):
    x.append(sarr[i])
    y.append(float(i+1)/l)

  return x,y
