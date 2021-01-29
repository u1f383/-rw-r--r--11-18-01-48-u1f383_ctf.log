#!/bin/bash
# https://bryceknowhow.blogspot.com/2018/05/cryptography-rsa-private-key-public-key.html

# get private component
cat pem.pem | openssl rsa -text -noout
