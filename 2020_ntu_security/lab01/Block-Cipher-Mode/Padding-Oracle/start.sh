#!/bin/bash
socat TCP-LISTEN:20000,fork EXEC:./server.py
