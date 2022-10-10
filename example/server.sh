#!/bin/bash

python3 -m http.server --bind ${1:-127.0.0.1} 8080
