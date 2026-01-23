msg = 'f8f11229044dfea54ddc214aaa439e7ea06b9b4ede8a3e3f6dfef500c9665598'
out = []
for i in range(0,len(msg),2):
    a = msg[i:i+2]
    int_format = int(a, 16)
    print("hex: "+ a +  ", int: " + str(int_format))
    out.append(int_format)
print(out)
