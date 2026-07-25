# Open a file to write the configuration
numUEs_range = [5,10,15,20,25,30,35,40,45,50]
numUAVS_cluster = 7
num_cluster = 3
numUAVs = numUAVS_cluster * num_cluster

for numUE in numUEs_range:
    name = f"/additional_disk1/ramiro/DRONES/EXAMPLE_1/samples/sim_1/configuration_{numUE}_{numUAVS_cluster}.xml"
    numSERVERs = numUE

    with open(name, "w") as configFile:

        j = 1
        
        # Write the static part of the configuration
        configFile.write("<config>\n")
        configFile.write("    <interface hosts='**' address='10.0.x.x' netmask='255.255.x.x'/>\n")
        configFile.write("    <route hosts='gat1' destination='upf%ppp0' netmask='255.255.255.255' gateway='iUpf%ppp1' interface='ppp0' metric='0'/>\n")
        configFile.write("    <route hosts='ue1[*]' destination='0.0.0.0' netmask='0.0.0.0' gateway='*' interface='cellular' metric='0'/>\n")
        configFile.write("    <route hosts='ue2[*]' destination='0.0.0.0' netmask='0.0.0.0' gateway='*' interface='cellular' metric='0'/>\n")
        configFile.write("    <route hosts='gnb*' destination='upf' netmask='255.255.255.255' gateway='*' interface='pppIf' metric='0'/>\n")
        configFile.write("    <route hosts='iUpf' destination='upf' netmask='255.255.255.255' gateway='*' interface='ppp0' metric='0'/>\n")
        configFile.write("    <route hosts='upf' destination='10.0.0.0' netmask='255.255.255.252' gateway='*' interface='pppIf' metric='0'/>\n")
        
        # Generate adh routes using loop
        for i in range(numUAVs):
            configFile.write(f"    <route hosts='adh[{i}]' destination='gnb{i}%x2ppp0' netmask='255.255.255.255' gateway='*' interface='ppp1' metric='0'/>\n")
        
        configFile.write("    <route hosts='gnb*' destination='0.0.0.0' netmask='0.0.0.0' gateway='*' interface='x2ppp0' metric='1'/>\n")
        
        # Generate server1 routes using loop
        for i in range(numSERVERs):
            configFile.write(f"    <route hosts='router' destination='server1[{i}]' netmask='255.255.255.255' gateway='*' interface='ppp{j}' metric='0'/>\n")
            j += 1
        
        # Generate server2 routes using loop
        for i in range(numSERVERs):
            configFile.write(f"    <route hosts='router' destination='server2[{i}]' netmask='255.255.255.255' gateway='*' interface='ppp{j}' metric='0'/>\n")
            j += 1
        
        # Write the closing tag
        configFile.write("</config>\n")

print("Configuration file generated successfully!")
