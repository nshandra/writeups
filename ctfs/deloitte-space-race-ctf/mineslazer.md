---
description: Crypto/PPC - 250 points
---

# MinesLazer

## Challenge Description:

Can you clear our path? There appears to be a bunch of mines along our trajectory.

#### Files:

* mineslazer.nim

### Firin mah lazer

#### Description:

Use your laser to remotely detonate all the mines!

#### Solution:

This challenge requires to solve a minesweeper-like 8x8 board by inputting the coordinates of the mines.  
Hitting a grid not containing a bomb means game over.

* ＿ means a blank grid
* Ｘ is a bomb
* Ｄ is a detonated bomb

The .nim file contains the challenge code written in Nimrod programing language, we can install a compiler with `apt-get install nim`, compile with nim compile `mineslazer.nim` and run it with `./mineslazer`.  
We need to solve the board that we receive when we `nc` to the CTF server, luckily we have **mineslazer.nim** so we can spin up a local version of the challenge.

```text
SAMPLE GAME
nc localhost 1234
=====================
=== MINESLAZER 4000  
=====================
Use the laser to remotely detonate the mines. 
Make sure you don't hit any crew members with the laser though!
[?] Enter laser position: 0
Wrong input.
[?] Enter laser position: 1,0
Pew pew pew! Bomb successfully detonated!
[＿Ｄ＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[＿＿＿＿＿＿＿＿]
[?] Enter laser position: 0,0
Yikes, you hit something you weren't supposed to hit.
Hope you have good insurance, you're on your own.
[＿Ｘ＿Ｘ＿＿Ｘ＿]
[＿＿＿ＸＸＸ＿Ｘ]
[Ｘ＿ＸＸＸＸＸ＿]
[ＸＸＸ＿Ｘ＿＿＿]
[＿＿Ｘ＿＿＿＿Ｘ]
[Ｘ＿＿＿ＸＸＸ＿]
[ＸＸ＿＿＿ＸＸＸ]
[Ｘ＿ＸＸＸ＿ＸＸ]
```

The grid is generated using the `mines` unsigned 64bit integer, each byte of this number is used as one of the rows of the grid. In this code the `y` loop iterates the bytes and `x` the bits of each byte.

```csharp
randomize()
...........
var mines = rand(uint64)
...........
proc minesGrid(mines: uint64, steps: uint64): string =
    var grid = ""
    for y in 0..7:
        grid &= "["

        for x in 0..7:
                if steps.testBit(x+y*8):
                    grid &= "Ｄ"
                elif mines.testBit(x+y*8):
                    grid &= "Ｘ"
                else:
                    grid &= "＿"

        grid &= "]\c\L"

    return grid
```

Lets modify _mineslazer.nim_ to also send the current grid `mines` uint64 in decimal, hex and binary form and the solved board.

```csharp
await client.send("uint64: " & $(mines) & "\c\L")
    await client.send("uint64 hex: " & $(mines.toHex(16)) & "\c\L")
    var bin = ""
    for i in 0..63:
        if mines.testBit(i):
            bin &= "1"
        else:
            bin &= "0"

    await client.send("uint64 hex: " & $(bin) & "\c\L")
    await client.send("Solved Grid:" & "\c\L")
    await client.send(minesGrid(mines, steps))
```

```csharp
uint64: 7659172545566270595
uint64 hex: 6A4AD8D9A3E6E483
uint64 bin: 1100000100100111011001111100010110011011000110110101001001010110
Solved Grid:
[ＸＸ＿＿＿＿＿Ｘ]
[＿＿Ｘ＿＿ＸＸＸ]
[＿ＸＸ＿＿ＸＸＸ]
[ＸＸ＿＿＿Ｘ＿Ｘ]
[Ｘ＿＿ＸＸ＿ＸＸ]
[＿＿＿ＸＸ＿ＸＸ]
[＿Ｘ＿Ｘ＿＿Ｘ＿]
[＿Ｘ＿Ｘ＿ＸＸ＿]
```

While verifying that the conversions were correct i noticed that the binary representation is reversed in python, meaning that they use different endianness.

```csharp
python3
>>> uint64 = '7659172545566270595'
>>> f'{int(uint64, 10):0>64b}'
'0110101001001010110110001101100110100011111001101110010010000011'


>>> import struct
>>> little_endian = (struct.unpack('<I', struct.pack('=I', 1))[0] == 1)
>>> little_endian
True


from pwn import *
>>> p64(int('7659172545566270595'), signed='unsigned', endian='big').hex()
'6a4ad8d9a3e6e483'
>>> p64(int('7659172545566270595'), signed='unsigned', endian='little').hex()
'83e4e6a3d9d84a6a'
```

Next, we need to address the random part of mines.  
Looking at mineslazer.nim we will see that the mines locations are generated using the [standard random number generator](https://nim-lang.org/docs/random.html), which is implemented using the [`xoroshiro128+`](https://prng.di.unimi.it/) library.  
Searching for weaknesses in the PRNG i found [this blog post](https://lemire.me/blog/2017/08/22/cracking-random-number-generators-xoroshiro128/) explaining that its posible to infer the state of the number generator if we know some of the previous outputs. The author also has a [link for a demo](https://github.com/lemire/crackingxoroshiro128plus).

The linked script needs a list of hex values from the previous random numbers to give us the next values.

```csharp
# Example:
python2 xoroshiftall.py 0xd42f7603a816cae9 0xbe57da5c9a3feb9a 0x455e790ff6007cf2 0x915263bcc91d1ef0
#1 = sat
state = 0xae421228117dee2fL 0x25ed63db9698dcba
state = 12556618674363821615 2732950343659347130
0xd42f7603a816cae9L
15289569018023168745
0xbe57da5c9a3feb9aL
13715671281439861658
0x455e790ff6007cf2L
4998565745886526706
0x915263bcc91d1ef0L
10471541746068954864
0xfc07e46a73e03381L
18160735168256553857
0x1e64be7b1080395cL
2190084754575997276
0x7a3d8e2f8837cb9fL
8808352781006523295
0xfa755ef462bde40bL
18047435485478773771
0xdb9f2fefb2e880b8L
15825420322148483256
0x8e6b5ab2bcb484deL
10262395899610432734
0x1e70c22a9da1d366L
2193466506818474854
0xf2705f4cdc197ea9L
17469567738284965545
0xbee4a8fb30a49c68L
13755304958702689384
0xdba08ed6e49dc762L
15825806144189613922
0x1ec735c379ef0310L
2217800455183860496
0xf24c70c9d16197d6L
17459453867512141782
0xe30f2ad6537040d3L
16361343071271534803
0xde3608c26f45568fL
16011995156345869967
0xd5849b1449813630L
15385592738439312944
0x7293dd64aaf0c01cL
8256185966334623772

#2 = unsat
```

With this info we have a plan: get several boards from the server, infer the PRNG state and generate the next board.  
This python script will solve the challenge by reversing several boards to their hex seed, pass these numbers to the `xoroshiftall.py` script and get the next random number to be used in order to input the necessary moves to solve the board.

```csharp
from pwn import *

def get_next_move(x, y):
    if x < 7:
        x += 1
    else:
        x = 0
        y += 1
    return x, y


def board_to_binary(board):
    striped_board = board.replace('[', '').replace(']', '').replace('\r\n', '')
    return striped_board.replace('Ｄ', '1').replace('Ｘ', '1').replace('＿', '0')[::-1]


def rand_int_to_binary_board(next_board_rand):
    binary_board = []
    binary = f'{int(next_board_rand, 10):0>64b}'[::-1]
    for i in range(0, 64, 8):
        binary_board.append(binary[i:i+8])
    return binary_board


def binary_to_board(binary_board):
    board = ''
    for line in binary_board:
        board += '[' + line + ']\n'
    return board


def binary_to_moves(binary_board):
    moves = []
    for y, byte in enumerate(binary_board):
        for x, bit in enumerate(byte):
            if bit == '1':
                moves.append(str(x) + ',' + str(y))
    return moves


def solve_board(moves):
    client = remote('localhost', 1234)
    for move in moves:
        log.info("move: %s", move)
        # log.info(client.sendlineafter('Enter laser position: ', move))
        client.sendlineafter('Enter laser position: ', move)
        answer = client.recvlineS()
        log.info(answer)
        if 'Yikes' in answer:
            client.recvlineS()
            board = client.recvallS()
            log.info(board)

    log.info(client.recvallS())
    client.close()


def get_next_mines_rand(hex_list_string, mines_rand_hex):
    command = "python2 xoroshiftall.py " + hex_list_string + " | grep -A 3 " + mines_rand_hex
    next_board_rand_list = process(command, shell=True).recvallS().split("\n")[0:4]
    log.info("next board random numbers: %s", next_board_rand_list[2:])
    return next_board_rand_list[3]


def get_board_rand_hex():
    client = remote('localhost', 1234)
    game_over = False
    x = 0
    y = 0
    mines_rand_hex = ''
    while not game_over:
        log.info("move: %i,%i", x, y)
        log.info(client.sendlineafter('Enter laser position: ', str(x) + ',' + str(y)))
        x, y = get_next_move(x, y)
        answer = client.recvlineS()
        log.info(answer)
        if 'Yikes' in answer:
            log.info(client.recvlineS())
            board = client.recvallS()
            log.info(board)
            game_over = True
            binary_board = board_to_binary(board)
            log.info("mines random number binary: %s", binary_board)
            log.info("mines random number: %s", int(binary_board, 2))
            mines_rand_hex = '0x' + p64(int(binary_board, 2), signed='unsigned', endian='big').hex()
    client.close()
    return mines_rand_hex


mines_rand_hex_list = []
boards_count = 4

for i in range(0, boards_count):
    mines_rand_hex_list.append(get_board_rand_hex())

hex_list_string = ' '.join(mines_rand_hex_list)
log.info("mines random numbers: %s", hex_list_string)

next_board_rand = get_next_mines_rand(hex_list_string, mines_rand_hex_list[-1])
binary_board = rand_int_to_binary_board(next_board_rand)
log.info("next board:\n%s", binary_to_board(binary_board))
moves = binary_to_moves(binary_board)
log.info("next board moves:\n%s", moves)
solve_board(moves)
```

