import subprocess


print("preparing to run nmap scan") 

target = input("Enter the target ip address: ")
print("you have entered: " target)    
subprocess.run(["nmap", "-Pn", "-sC", "-sV"] target)

