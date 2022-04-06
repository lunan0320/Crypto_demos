
from Des_attack import *

N=5#明密文对数

P_1_box =[
      9, 17, 23, 31, 13, 28, 2, 18,
      24, 16, 30, 6, 26, 20, 10, 1,
      8, 14, 25, 3, 4, 29, 11, 19,
      32, 12, 22, 7, 5, 27, 15, 21
]

hex_bin = {
        '0': '0000', '1': '0001', '2': '0010', '3': '0011',
        '4': '0100', '5': '0101', '6': '0110', '7': '0111',
        '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
        'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111',
        ' ': '0000'
}
# plaintext=["5E870BA0B559A8CF","E7C1F970B559A8CF",
#            "5D6F0803ED9FAC45","1EB2B007ED9FAC45",
#            "7ECF80BD2FE0EA99","8B2CBE002FE0EA99",
#            "97D2078984F010B4","4A5C783384F010B4",
#            "641E10E96186B8A0","CA4E94596186B8A0"
#            ]
# ciphertext=["71BF939C0CEEE3B1","EAA6CE7BC9DB808B",
#             "D99FDDD5A3016E53","B49E2F61B4172078",
#             "C9BE22F6DA261B9A","2360C6F9ACD3982D",
#             "719849F28E5313BF","E4DDEEDB66776D42",
#             "7918C1C6400F4AA2","B8D0DC72CD2F6579"
#             ]

plaintext=[];ciphertext=[]
with open('text.txt','r',encoding='utf-8') as fp:
    text=fp.readlines()
    for i in range(2*N):
        plaintext.append(text[i][5:21:])
        ciphertext.append(text[i][27:43:])
#将明密文转换成二进制的列表
def String_bin(text):
    for M in text:
        m = M.lower()
        # 转为二进制
        text[text.index(M)] = ''.join(hex_bin[i] for i in m)


def hex2bin(text):
    for m in text:
        text=''.join(hex_bin[m])
    return text

String_bin(plaintext)
String_bin(ciphertext)

#求输入差分L0与L0*的差分
################################注意此处是10个明密文，在索引的时候一定是2*i或者2*i+1 ##############################
def L_xor(text):
    L0_xor_list=[]
    for i in range(N):
        P1 = text[2*i]
        P2 = text[2*i + 1]
        L0_1 = P1[0:32]
        L0_2 = P2[0:32]
        L0_xor = ''.join('0' if L0_1[j] == L0_2[j] else '1' for j in range(0,32))
        L0_xor_list.append(L0_xor)
    return L0_xor_list

#求输出差分R3与R3*的差分
def R3_xor(ciphertext):
    R3_xor_list=[]
    for i in range(N):
        C1 = ciphertext[2*i]
        C2 = ciphertext[2*i + 1]
        R3_1 = C1[32:64]
        R3_2 = C2[32:64]
        R3_xor = ''.join('0' if R3_1[j] == R3_2[j] else '1' for j in range(32))
        R3_xor_list.append(R3_xor)
    return R3_xor_list

#将十进制转换成六位二进制
def int_bin6(int_x):
    a = bin(int_x)[2:]
    list_a = list(a)
    length = len(a)
    while length < 6:
        list_a.insert(0, '0')
        length += 1
    a = ''.join(list_a)
    return a

#六位二进制字符串过第n个S盒
def S(B,n):
    S_box_location =int(B[0] + B[-1], 2) * 16 + int(B[1:-1], 2)
    R = ''.join(hex_bin[hex(S_box[n][S_box_location])[-1]])
    return R

#S盒两个四位输出结果的差分
def S_box_xor(s1,s2):
    xor=''.join('0' if s1[i]==s2[i] else '1' for i in range(4))
    return int(xor,2)

#差分表
def Difference_table():
    table=[[[[]for k in range(16)] for i in range(64)]for j in range(8)]
    for n in range(8):
        for B1 in range(64):
            for B2 in range(64):
                B1_bin = int_bin6(B1)
                B2_bin = int_bin6(B2)
                S_B1 = S(B1_bin, n)
                S_B2 = S(B2_bin, n)
                S_xor=S_box_xor(S_B1,S_B2)
                table[n][B1 ^ B2][S_xor].append(B1)
    return table
table=Difference_table()
print(table)
#求输入差分和输出差分的异或结果
def xor(L_xor_list,R_xor_list):
    xor_list=[]
    for i in range(N):
        L_xor=L_xor_list[i]
        R_xor=R_xor_list[i]
        xor = ''.join('0' if L_xor[j] == R_xor[j] else '1' for j in range(32))
        xor_list.append(xor)
    return xor_list

def P_1(xor_list):
    P_1_list=[]
    for i in range(N):
        P_1_list.append(translation(xor_list[i],P_1_box))
    return P_1_list

#B_xor_B*
def B_xor_List():
    L3_xor_list = L_xor(ciphertext)
    B_xor_list=[]
    for m in L3_xor_list:
        text=translation(m,E)
        B_xor_list.append(text)
    return B_xor_list

B_xor_list=B_xor_List()#B异或B*
L=L_xor(plaintext)#输入差分
R=R3_xor(ciphertext)#输出差分
L0_R3_xor_list=xor(L,R)#差分异或
S1_xor_S2_list=P_1(L0_R3_xor_list)#P逆差分异或,S(B)^S(B*)
print("L0^L0*",L)
print("R3^R3*",R)
print("L0'^R3'",L0_R3_xor_list)
print("P逆(S(B)^S(B*))",S1_xor_S2_list)
#E扩展之后的L3的取值列表
###################################################注意此处也是2*N的索引，整个ciphertext是有10个###########################
def find_E_L3_list():
    E_L3_list = []
    for i in range(2*N):
        C = ciphertext[i]
        L3 = C[0:32]
        E_L3_list.append(translation(L3, E))
    return E_L3_list

E_L3_list=find_E_L3_list()


# 寻找K3可能出现的情况
def Differ_KEY3():
    key=[[]for i in range(8)]
    for k in range(N):
        bit6_list = [B_xor_list[k][i:i + 6] for i in range(0, 48, 6)]  # 将B^B*按6bit分组
        bit4_list = [S1_xor_S2_list[k][i:i + 4] for i in range(0, 32, 4)]  # 将S(B)^S(B*)按4bit分组
        ################################################注意此处，索引L3时候是2*k，因为E_L3_list是有10组，必须要单独的去取那一组#############################################
        bit6_list_L3=[E_L3_list[2*k][i:i+6]for i in range(0,48,6)] #对所有扩展后的L3，每一组明密文对中按6bit分组
        for i in range(8):
            row=int(bit6_list[i],2)
            col=int(bit4_list[i],2)
            for B in table[i][row][col]:
                B=int_bin6(B)
                E_L3=bit6_list_L3[i]
                K3 = ''.join('0' if B[j] == E_L3[j] else '1' for j in range(6))
                K3=int(K3,2)
                key[i].append(K3)
    return key

key3_list=Differ_KEY3()


###############################在k3所有可能值的列表中，找到每一个列表中出现次数最多的（5次）的k3，将其添加到k3
k3=[]
for key3 in key3_list:
    k3.append(list({max(key3,key=key3.count)}))

# 将k3列表中的元素单独组成一个字符串，以16进制的格式打印出来
right_k3 = ''
for item in k3:
    for k in item:
        right_k3+='{:0>6}'.format(bin(k)[2:])
#print(right_k3)
print("right_k3_48",hex(int(right_k3,2)))


PC_1=[57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
      63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]

PC_1_1=[8, 16, 24, 56, 52, 44, 36, -1, 7, 15, 23, 55, 51, 43, 35, -1, 6, 14, 22, 54, 50, 42, 34, -1, 5, 13, 21, 53, 49, 41, 33, -1,
        4, 12, 20, 28, 48, 40, 32, -1, 3, 11, 19, 27, 47, 39, 31, -1, 2, 10, 18, 26, 46, 38, 30, -1, 1, 9, 17, 25, 45, 37, 29, -1]

PC_2=[14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,
      31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

K56_48 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]
Kleft_shift = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
K64_56 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

def round3_DES(P,test_Key):
    #拿到的test_Key是56位的,P是不需要过IP置换的，最后也不需要过IP逆置换

    # 获取三轮轮秘钥 Kn，没有用global关键字，应该没有问题，如果有问题回来看一下
    Cn = [test_Key[:28]]
    Dn = [test_Key[28:]]
    for i in range(3):
        Cn.append(Cn[-1][Kleft_shift[i]:] + Cn[-1][:Kleft_shift[i]]) #注意轮秘钥K1的下标是1
        Dn.append(Dn[-1][Kleft_shift[i]:] + Dn[-1][:Kleft_shift[i]])
    Kn = [translation(Cn[i] + Dn[i], K56_48) for i in range(1, 4)]

    # 开始加密过程
    #print("P1",P)
    #p = ''.join(hex_bin[i] for i in P)
    #print("P2",p)
    l = P[0:32]
    r = P[32:]
    for i in range(3):
        # print("{:<10}Round{}".format(' ',i + 1))
        # print('{:<4}        {}'.format('Ki', Kn[i]))
        l, r = festial(l, r, Kn[i])
        # print('{:<4}        {}'.format('r', r))
        # print('{:<4}        {}\n'.format('l', l)
    return l + r

def getkey56(key48):
    temp_Key = ['6'] * 56

    # 先过PC2的逆
    for i in range(48):
        temp_Key[K56_48[i] - 1] = key48[i]

    # print(temp_Key)
    temp_Key = ''.join(temp_Key)
    # print('key48',temp_Key)

    temp_Key_l = temp_Key[:28]
    temp_Key_r = temp_Key[28:]
    # print('temp_Key_l',temp_Key_l)
    # print('temp_Key_r',temp_Key_r)
    shift = Kleft_shift[0] + Kleft_shift[1] + Kleft_shift[2]
    Key56_l = temp_Key_l[-shift:] + temp_Key_l[:-shift]
    Key56_r = temp_Key_r[-shift:] + temp_Key_r[:-shift]
    # print(Key56_l)
    # print(Key56_r)
    temp_Key56 = Key56_l + Key56_r
    #print(temp_Key56)

    # 穷举Key56的剩余位置，然后经过一次三轮加密，
    # 先找到需要猜测的秘钥位置,顺便初始化一下， 注意字符串是不可变的（不可以用下标索引来修改，但是可以下标访问）
    guess_Key = ['0'] * 56
    guess_loca = []
    for i in range(56):
        if temp_Key56[i] == '6':
            guess_loca.append(i)  # 注意此处下标从0开始算的
        else:
            guess_Key[i] = temp_Key56[i]
    #print('guess_loca',guess_loca)
    right_Key56 = ''
    for i in range(2 ** 8):
        guess = '{:0>8}'.format(bin(i)[2:])
        for j in range(8):
            guess_Key[guess_loca[j]] = guess[j]
        test_Key = ''.join(guess_Key)
        #print(test_Key)
        # 接下来要用我们的test_Key去计算三轮秘钥，然后跑一次DES，如果可以把明文顺利加密为密文，就说明这个是对的秘钥
        p_lower=plaintext[0]
        test_cipher=round3_DES(p_lower, test_Key)
        #print("p",test_cipher)
        c_lower=ciphertext[0]
       # print("c",c_lower)
        if test_cipher == c_lower:
            right_Key56 = test_Key
            break
    print("right_Key56",hex(int(right_Key56,2)).upper())
    return right_Key56
    # # 过PC1逆置换得到Key64的56个位置，剩余的位置是奇偶校验位
    # temp_Key64 = ['0'] * 64  # 默认全是0，就是说如果某7bit的和是odd number，就可以改为1,这里使用偶校验
    # for i in range(56):
    #     temp_Key64[K64_56[i] - 1] = right_Key56[i]  # 注意下标减1
    # for i in range(8):
    #     sum = 0
    #     for j in range(7):
    #         sum = (sum + int(temp_Key64[i * 8 + j], 2)) % 2
    #     if not sum % 2 == 0:
    #         temp_Key64[i * 8 - 1] = '1'
    # return ''.join(temp_Key64)
def getkey64(key56):
    key56_=''.join(key56[i-1] for i in PC_1_1 if i!=-1)
    key64=''
    for i in range(8):
        key64+=key56_[7*i:7*(i+1):]+str((key56_[7*i:7*(i+1):].count('1')+1)%2)
    return key64
key_56=getkey56(right_k3)
right_key = ''
right_key=getkey64(key_56)
print("right_key",hex(int(right_key,2)).upper())

