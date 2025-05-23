import argparse
import math as math
from prettytable import PrettyTable
import mpmath

parser = argparse.ArgumentParser(prog='python3 main.py', description='find appropriate decomposition parameters with '
                                                                     'given target depth of computation, or directly '
                                                                     'compute errors from given parameters')
parser.add_argument('-t', '--type', nargs=1, default=[1], type=int, choices=[1, 2],
                    help='type: 1 for CMUX;\n 2 for automorphism')
parser.add_argument('-n', nargs='?', type=int, help='n, default to 571 for type 1, 458 for type 2')
parser.add_argument('-N', nargs=1, default=[2048], type=int, help='N, default to 2048')
parser.add_argument('-v', nargs=1, default=[3], type=int, help='vartheta, default to 3')
parser.add_argument('-q', nargs=1, default=[1024], type=int, help='q, default to 1024')
parser.add_argument('-Q', nargs=1, default=[2 ** 54], type=int, help='Q, default to 2^54')
parser.add_argument('-D', nargs=1, default=[1000], type=int, help='target max depth, default to 1000')
parser.add_argument('--dump', action='store_true', help='dump all qualified data in the file dump+D.txt')
parser.add_argument('-c', action='store_true', help='computation with 5 sets of decomposition parameters')
parser.add_argument('-l', nargs=5, type=int, help='decomposition lengths to compute')
parser.add_argument('-B', nargs=5, type=int, help='exponents of the bases to compute')
parser.add_argument('-prec', nargs='?', type=int, help='bit precision when computing error rate of sparse rounding, '
                                                       'default to 53')
parser.add_argument('-opt', action='store_true', help='use algorithm determined bases for decomposition')
parser.add_argument('-s', nargs=1, default=[1600], type=int, help='target sigma_in^2, default to 1600')

args = parser.parse_args()
t = args.type[0]
if t == 1:
    n = 742
else:
    n = 458
N = args.N[0]
v = args.v[0]
q = args.q[0]
Q = args.Q[0]
D = args.D[0]
if args.prec is not None:
    mpmath.mp.prec = args.prec
if args.c:
    l1 = args.l[0]
    l2 = args.l[1]
    l3 = args.l[2]
    l4 = args.l[3]
    l5 = args.l[4]
    if not args.opt:
        B1 = args.B[0]
        B2 = args.B[1]
        B3 = args.B[2]
        B4 = args.B[3]
        B5 = args.B[4]
s = args.s[0]

# additional parameters
skey = 3.2   # sigma_key
na = 368  # number of automorphisms
w = 15  # window size


def error_ms():
    res = 4 * N * N * s / q / q
#    if q > 2 * N / 2 ** v:
#    if t == 1:
#        res += (n + 2) * 2 ** (2 * v) / 24 - (n - 4) * N * N / 12 / q / q
#    else:
#        res += (n * skey * skey + 1) * (2 ** (2 * v) / 12 + 2 * N * N / 3 / q / q) - N * N / q / q

    er = mpmath.log(mpmath.erfc(N / 2 / mpmath.sqrt( 2* res)), 2)
    return res, er


def error_br(l1, b1, l2, b2, t):
    ebr1 = math.ceil(2 ** (math.log(Q, 2) - l1 * b1)) / 2
    ebr2 = math.ceil(2 ** (math.log(Q, 2) - l2 * b2)) / 2
    temp = n * (N * l1 * (2 ** (2 * b1)) / 6 * skey * skey + (N + 1) * ebr1 * ebr1 / 3)
    if t == 1:
        res = 2 * temp
    else:
        res = temp + na * (N * l2 * (2 ** (2 * b2)) / 12 * skey * skey + N * ebr2 * ebr2 / 6)
    return res


def error_trace(l3, b3):
    ebr = math.ceil(2 ** (math.log(Q, 2) - l3 * b3)) / 2
    res = (N * N - 1) / 3 * (N * l3 * (2 ** (2 * b3)) / 12 * skey * skey + N * ebr * ebr / 6)
    return res


def error_ss(l4, b4):
    ebr = math.ceil(2 ** (math.log(Q, 2) - l4 * b4)) / 2
    res = N * l4 * (2 ** (2 * b4)) / 12 * skey * skey + N * N * ebr * ebr / 12
    return res


def noise_sum(ss, l5, b5):
    ebr = math.ceil(2 ** (math.log(Q, 2) - l5 * b5)) / 2
    noise = l5 * (2 ** (2 * b5)) * ss * N / 6 + (N + 1) * ebr * ebr / 3
    return noise


def max_depth(noise):
    if t == 1:
        temp = (n + 2) / 24
    else:
        temp = (n * skey * skey + 1) / 12
    res = (s - temp) * Q * Q / q / q / noise
    return res


def optimize_cumx_br(l):
    b = math.log(Q * Q * (N + 1) / N / skey / skey / 2, 2) / 2 / (l + 1)
    b1 = math.floor(b)
    b2 = b1 + 1
    if error_br(l, b1, 0, 0, 1) < error_br(l, b2, 0, 0, 1):
        return b1
    return b2


def optimize_auto_br(l):
    b = math.log(Q * Q / skey / skey / 2, 2) / 2 / (l + 1)
    b1 = math.floor(b)
    b2 = b1 + 1
    if error_trace(l, b1) < error_trace(l, b2):
        return b1
    return b2


def optimize_trace(l):
    b = math.log(Q * Q / skey / skey / 2, 2) / 2 / (l + 1)
    b1 = math.floor(b)
    b2 = b1 + 1
    if error_trace(l, b1) < error_trace(l, b2):
        return b1
    return b2


def optimize_ss(l):
    b = math.log(Q * Q * N / skey / skey / 4, 2) / 2 / (l + 1)
    b1 = math.floor(b)
    b2 = b1 + 1
    if error_ss(l, b1) < error_ss(l, b2):
        return b1
    return b2


def optimize_noise(ss, l):
    b = math.log(Q * Q / ss / N * (N + 1) / 2, 2) / 2 / (l + 1)
    b1 = math.floor(b)
    b2 = b1 + 1
    if noise_sum(ss, l, b1) < noise_sum(ss, l, b2):
        return b1
    return b2


if __name__ == '__main__':
    # parsing args
    args = parser.parse_args()
    t = args.type[0]
    if t == 1:
        n = 571
    else:
        n = 458
    N = args.N[0]
    v = args.v[0]
    q = args.q[0]
    Q = args.Q[0]
    D = args.D[0]
    if args.prec is not None:
        mpmath.mp.prec = args.prec
    if args.c:
        l1 = args.l[0]
        l2 = args.l[1]
        l3 = args.l[2]
        l4 = args.l[3]
        l5 = args.l[4]
        if not args.opt:
            B1 = args.B[0]
            B2 = args.B[1]
            B3 = args.B[2]
            B4 = args.B[3]
            B5 = args.B[4]

    # print basic info
    print('Target Output LWE:\t'+str(s))
    if t == 1:
        a = 'CMUX'
    else:
        a = 'AUTO'
    print('Type:\t\t\t' + a)
    res, er = error_ms()
    print('Sparse Rounding Error:\t' + str(res))
    print('(log2) Error Rate:\t' + str(er) + '\n')

    print('Basic Parameters:')
    print('n:\t\t\t'+str(n))
    print('N:\t\t\t'+str(N))
    print('vartheta:\t\t'+str(v))
    print('q:\t\t\t'+str(q))
    print('Q:\t\t\t'+str(Q))
    print('sigma_key:\t\t'+str(skey))
    print('window size:\t\t' + str(w))
    print('#Automorphism:\t\t'+str(na))
    print('')

    if args.c:
        # direct computation
        # set up pretty table
        print('Decomposition parameters:')
        tab = PrettyTable(['', 'l', 'B'])

        # br
        if args.opt:
            B1 = optimize_cumx_br(l1)
            B2 = optimize_auto_br(l2)
        err_br = error_br(l1, B1, l2, B2, t)
        tab.add_row(['CMUX br', l1, '2^' + str(B1)])
        if t == 2:
            tab.add_row(['Auto br', l2, '2^' + str(B2)])

        # trace
        if args.opt:
            B3 = optimize_trace(l3)
        err_trace = error_trace(l3, B3)
        tab.add_row(['Trace', l3, '2^' + str(B3)])

        # scheme switching
        if args.opt:
            B4 = optimize_ss(l4)
        err_ss = error_ss(l4, B4) + N*0.5*err_trace+0.5*err_br
        tab.add_row(['SS', l4, '2^' + str(B4)])

        # noise
        if args.opt:
            B5 = optimize_noise(err_ss, l5)
        noise = noise_sum(err_ss, l5, B5)
        tab.add_row(['Noise Sum', l5, '2^' + str(B5)])

        # key size
        if t == 1:
            ks1 = (2 * n * l1) * 2 * N * math.log(Q, 2) / 2 ** 23
        else:
            ks1 = (2 * n * l1 + (w + 2) * l2) * 2 * N * math.log(Q, 2) / 2 ** 23
        ks2 = (math.log(N, 2) * l3 + l4) * 2 * N * math.log(Q, 2) / 2 ** 23

        # NTTs
        if t == 1:
            nntt1 = 2 * n * (l1 + 1)
        else:
            nntt1 = 2 * n * (l1 + 1) + (na + 2) * (l2 + 1)
        nntt2 = round(math.log(N, 2) * (l3 + 1) + l4 + 1) * l5

        print(tab)
        print('Bootstrapping Error:\t' + str(math.log(err_br, 2)))
        print('Trace Error:\t\t' + str(math.log(err_trace, 2)))
        print('Scheme-Switching Error:\t' + str(math.log(err_ss, 2)))
        print('Noise Sum:\t\t' + str(math.log(noise, 2)))
        depth = max_depth(noise)
        print('Max Depth:\t\t' + str(depth))
        print('Key Size I (MB):\t' + str(ks1))
        print('Key Size II (MB):\t' + str(ks2))
        print('Key Size Total (MB):\t' + str(ks1 + ks2))
        print('# NTTs I:\t\t' + str(nntt1))
        print('# NTTs II:\t\t' + str(nntt2))
        print('# NTTs Total:\t\t' + str(nntt1 + nntt2))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
