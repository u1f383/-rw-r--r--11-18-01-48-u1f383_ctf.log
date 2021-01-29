#!/usr/bin/python3

table = open('./qq.txt', 'r').read()


def enc():
    a = input('> ')

    for i in range(len(a)):
        for j in range(len(table) // 2):
            if a[i] == table[j*2]:
                print(table[j*2+1], end='')
                break

def dec():
    a = input('> ')

    for i in range(len(a)):
        for j in range(len(table) // 2):
            if a[i] == table[j*2+1]:
                print(table[j*2], end='')
                break

dec()
