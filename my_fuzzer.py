import random as rand
import sys

#-----------------------------------------
def testFunction(a,b,c):
    x, y, z = 0, 0, 0
    if (a):
        x = -2
    if (b < 5):
        if (not a and c):
            y = 1
            z = 2
    assert(x + y + z != 3)
#-----------------------------------------

def main():
    while True:
        a = rand.randint(-200, 200)
        b = rand.randint(-200, 200)
        c = rand.randint(-200, 200)
        print(a,b,c)
        testFunction(a,b,c)

if __name__ == "__main__":
    main()