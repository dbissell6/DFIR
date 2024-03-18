# Cyber Apocalypse 2024 - Hack The Box(HTB)

![image](https://github.com/dbissell6/DFIR/assets/50979196/f773fc8d-3c31-42f3-b955-ca52a8eba356)

# Misc

## Path of Survival - hard

This challenge presented us with a 2d grid and required us to find a path for the player to reach his weapon before time ran out. Each tile had a terrain attribute and these determined the cost of 'time' for each move. In order to get the flag we have to solve the problem 100 times in a row. 

![image](https://github.com/dbissell6/DFIR/assets/50979196/850dcbe5-f3bd-472f-91b9-96130a0d9437)

Time costs

![image](https://github.com/dbissell6/DFIR/assets/50979196/56390dc1-8bf2-4a16-b458-3fdaf5710fa2)

Luckily, it also comes with an API.

![image](https://github.com/dbissell6/DFIR/assets/50979196/8a25efe4-e802-4975-965c-74e24b51f6b4)

From a grid to graph

Path traversal is a common use of graph theory. We can represent this problem in graph. Each tile is a node, and the tiles that connect left/right and up/down are connected with edges in the graph.

![image](https://github.com/dbissell6/DFIR/assets/50979196/aedd4b35-1372-4b69-a9f8-9103ff89ff96)


Once we have reconceptualized this to a graph problem the script takes form.

1) Create nodes with attributes(terrain)
2) Create the edges
3) Update edge weights to time costs
4) Trim edges(cliffs + geysers) + remove nodes (empty)
5) Use dijkstra algo to find shortest path
6) Convert path to moves
   
Script in action

![image](https://github.com/dbissell6/DFIR/assets/50979196/758b434a-f68b-48aa-9446-a81aaa1a020c)

![image](https://github.com/dbissell6/DFIR/assets/50979196/c207a01f-6be3-46af-a8b7-c039d49aae74)


<details>
<summary> Python code </summary>

```
import requests
import networkx as nx


# Base URL for the API
BASE_URL = 'http://{IP:PORT}'  # replace with the actual base URL

def get_rules():
    response = requests.get(f"{BASE_URL}/rules")
    return response.text

def regenerate_map():
    response = requests.get(f"{BASE_URL}/regenerate")
    return response.json()

def get_map():
    response = requests.post(f"{BASE_URL}/map", data={})
    return response.json()

def update_direction(direction):
    headers = {'Content-Type': 'application/json'}
    data = {"direction": direction}
    response = requests.post(f"{BASE_URL}/update", json=data, headers=headers)
    return response.json()


def create_graph(map):
    tiles = map['tiles']
    # Create a new graph
    G = nx.DiGraph()
    # Add nodes with attributes
    for position, tile_info in tiles.items():
        # Convert the position string to a tuple (x, y), which will be used as the node identifier
        position = position.replace('(','').replace(')','').split(', ')
        pp = int(position[0]), int(position[1])
        #Add the node to the graph with 'has_weapon' and 'terrain' as attributes
        G.add_node(pp, has_weapon=tile_info['has_weapon'], terrain=tile_info['terrain'],player_position=False)
    # Add player to tile
    up=tuple((map['player']['position']))
    G.nodes[up] ['player_position'] = True

    return G

def create_links(G,map_size):
    # Assuming the map is a grid and each tile can connect to its adjacent tiles (up, down, left, right)
    for x in range(map_size['width']):
        for y in range(map_size['height']):
            if x > 0:
                G.add_edge((x, y), (x-1, y))  # Edge to the left
            if x < map_size['width'] - 1:
                G.add_edge((x, y), (x+1, y))  # Edge to the right
            if y > 0:
                G.add_edge((x, y), (x, y-1))  # Edge above
            if y < map_size['height'] - 1:
                G.add_edge((x, y), (x, y+1))  # Edge below

    # remove all empty tiles
    nodes_to_remove = [node for node, attr in G.nodes(data=True) if attr.get('terrain') == 'E']
    for node in nodes_to_remove:
        G.remove_node(node)
    return G

def update_edge_weights(G):

    terrain_weights={('P','M'):5, ('M','P'):2, ('P','S'):2, ('S','P'):2, ('P','R'):5,('R','P'):5,
                     ('M','S'):5, ('S','M'):7, ('M','R'):8, ('R','M'):10, ('S','R'):8, ('R','S'):6}

    cg =['C','G']
    def get_terrain_weight(node1, node2, terrain_weights):
        terrain1 = G.nodes[node1]['terrain']
        terrain2 = G.nodes[node2]['terrain']
        if terrain1 == terrain2 or terrain1 in cg or terrain2 in cg:
            return 1
        return terrain_weights.get((terrain1, terrain2))


    for node1, node2 in G.edges():
        weight = get_terrain_weight(node1, node2, terrain_weights)
        G[node1][node2]['weight'] = weight

    return G

def trim_CG_edges(G):
    for node in list(G.nodes):
        terrain = G.nodes[node]['terrain']
        to_delete = []
        x, y = node  # Assuming node is a tuple (x, y)

        if terrain == 'C':
            # For 'C', delete edges coming from below (y+1) or to the right (x+1)
            for edge in G.in_edges(node, data=True):
                src_x, src_y = edge[0]  # Source node coordinates
                # Check if the source node is to the right or below
                if src_y == y+1 or src_x == x+1:
                    to_delete.append((edge[0], node))

        elif terrain == 'G':
            # For 'G', delete edges coming from above (y-1) or to the left (x-1)
            for edge in G.in_edges(node, data=True):
                src_x, src_y = edge[0]  # Source node coordinates
                # Check if the source node is above or to the left
                if src_y == y-1 or src_x == x-1:
                    to_delete.append((edge[0], node))

        # Remove the identified edges
        for src, dst in to_delete:
            G.remove_edge(src, dst)

    return G


def find_shortest_path_to_weapon(G):
    
    
    # First, find all nodes with a weapon
    weapon_nodes = [node for node, attr in G.nodes(data=True) if attr.get('has_weapon')]
    start_node = [node for node,  attr in G.nodes(data=True) if attr.get('player_position')] 
    start_node = start_node[0]
    print("Start at:",start_node,'-',"Targets are:",weapon_nodes)
    # Initialize variables to store the shortest path and its length
    shortest_path = None
    shortest_path_length = float('inf')

    # Go through each weapon node and find the shortest path from the start node to it
    for weapon_node in weapon_nodes:
        try:
            path = nx.dijkstra_path(G, start_node, weapon_node, weight='weight')
            path_length = nx.dijkstra_path_length(G, start_node, weapon_node, weight='weight')

            # Check if the path found is shorter than the previously found paths
            if path_length < shortest_path_length:
                shortest_path = path
                shortest_path_length = path_length

        except nx.NetworkXNoPath:
            # There is no path to this weapon node, continue to the next
            continue

    return shortest_path, shortest_path_length    



def path_to_moves(path):
    moves = []
    for i in range(1, len(path)):
        previous_node = path[i - 1]
        current_node = path[i]
        dx = current_node[0] - previous_node[0]
        dy = current_node[1] - previous_node[1]

        if dx == 1:
            moves.append('R')  # Move right
        elif dx == -1:
            moves.append('L')  # Move left
        elif dy == 1:
            moves.append('D')  # Move down
        elif dy == -1:
            moves.append('U')  # Move up

    return ''.join(moves)



def run_simulation():
    # Initialize/reset all necessary variables or state here
    map_info = get_map()
    G = create_graph(map_info)
    G = create_links(G, map_info)
    G = update_edge_weights(G)
    G = trim_CG_edges(G)

    sp, spl = find_shortest_path_to_weapon(G)

    if sp:
        print('Shortest Path:',sp,'-','Shortest length:', spl)
        moves = path_to_moves(sp)
        print(moves)

    if moves:
        for move in moves:
            update_result = update_direction(move)
            print("Update Result:", update_result)
            # Check if you need to reset based on update_result or another condition
            if 'error' in update_result:
                return False  # Signal that a reset is needed
    return True  # Signal that everything went fine

def main():
    attempts = 0
    while attempts < 100:
        print('')
        print(f"Attempt {attempts + 1} of 100")
        if not run_simulation():
            print("Resetting...")
            attempts = 0
            continue  # This will skip the increment below and retry the simulation
        attempts += 1

if __name__ == "__main__":
    main()
    
```

</details>

## Stop Drop and Roll - very easy 

nc connection translating sets of words many many times.

![image](https://github.com/dbissell6/DFIR/assets/50979196/b8c297ff-d040-455d-818d-346ee44176d8)


![image](https://github.com/dbissell6/DFIR/assets/50979196/5c53c267-87e5-4c64-8dc7-9e0d0dc6e166)


<details>
<summary> Python pwntools code </summary>

```
from pwn import *
import time

# Set up a remote connection to the game server
game = remote('IP', PORT)

time.sleep(2)
# Send 'y' to indicate we're ready to start the game
game.sendline('y')
game.clean()
# Assume we have already connected to the game and sent 'y'

# Define the responses for the game's challenges
responses = {
    'GORGE': 'STOP',
    'PHREAK': 'DROP',
    'FIRE': 'ROLL',
}

# Function to generate a response based on the challenge from the game
def generate_response(challenges):
    x = challenges.split()
    x = [y.replace(',','') for y in x]
    return '-'.join(responses[challenge] for challenge in x if challenge in responses.keys())

# Main loop
x = 0
while True:
    time.sleep(1)
    x += 1
    # Read the line that asks "What do you do?"
    line = game.recv().decode().strip()
    print('')
    print(f'This has been going on {x} times')
    print(line)
    challenge = line
    # Check if the line is a challenge
    response = generate_response(challenge)
    # Send the response to the game
    last_response = None
    c = 0
    if response:
        print(response)
        last_response=response
        c = 0
        game.sendline(response)
        #game.clean()
    c += 1
    if c > 3:
        print(' *** it worked ***')
        game.sendline(response)

     
```

</details>


## Character

# Forensics

## It Has Begun - very easy

Given .sh

Base64 encoded strings containing the flag.

![Pasted image 20240309061317](https://github.com/dbissell6/DFIR/assets/50979196/0b74e42e-04c7-478b-bf7e-5cefdad41e1d)

## An unusual sighting - very easy

Given .log and bash_history.txt

![Pasted image 20240309213743](https://github.com/dbissell6/DFIR/assets/50979196/3b6c5e29-340d-4ac7-9e42-eb673abf6fd7)

![Pasted image 20240309214234](https://github.com/dbissell6/DFIR/assets/50979196/60d46b14-ff66-439e-be94-ceaec8e1ecd3)

![Pasted image 20240313181403](https://github.com/dbissell6/DFIR/assets/50979196/f6072925-0211-48ac-a1ee-a6e09be53dce)

## Urgent - very easy

Given .eml

![Pasted image 20240309061554](https://github.com/dbissell6/DFIR/assets/50979196/be87190b-6ecd-4a3a-b12d-d305905f5cf6)

## Pursue The Tracks - easy

Given mft

Used a mix of mft explorer and MFTEcmd -> timeline explorer. 

![Pasted image 20240309220155](https://github.com/dbissell6/DFIR/assets/50979196/97993d71-b64a-4a99-8ca8-eaad13a7adcb)

![Pasted image 20240309220114](https://github.com/dbissell6/DFIR/assets/50979196/4647438f-eef5-46e3-b797-2ecf3e2522fd)

![Pasted image 20240313181643](https://github.com/dbissell6/DFIR/assets/50979196/316e735c-0eda-475a-9210-c617b1b9dfbb)

## Fake Boost - easy 

Given pcap

pcap contained malicious script. the first part of the flag was in the script along with the algorithm to decrypt packets that had the other half of the flag.

![Pasted image 20240309224006](https://github.com/dbissell6/DFIR/assets/50979196/d864f0c7-a475-4b3e-bd1a-ac4d346d9070)

![Pasted image 20240309063750](https://github.com/dbissell6/DFIR/assets/50979196/54d18958-ee92-4f1c-86db-688aedcf7cc1)

![Pasted image 20240309063448](https://github.com/dbissell6/DFIR/assets/50979196/566872cc-3fb1-4dcb-8f9e-f33f49f340e1)

This is the big part, we see after message is encrypted, the IV is added to the beginning, then base64, then sent. We need to reverse the base64 take the first 16 bytes off and they will be our IV.

![Pasted image 20240311203313](https://github.com/dbissell6/DFIR/assets/50979196/f44a05f7-c62d-483b-95ae-53828b1f0b8c)

The pcaps in question, from the malicious script.

![Pasted image 20240311203857](https://github.com/dbissell6/DFIR/assets/50979196/2ac63975-40a8-4143-8486-3270f0ac6ff5)

![Pasted image 20240311203929](https://github.com/dbissell6/DFIR/assets/50979196/395d8bcc-8cae-4f3a-8692-edcc82cefead)

To get IV

![Pasted image 20240311203228](https://github.com/dbissell6/DFIR/assets/50979196/376bf879-a02f-4378-8843-c81b100e153c)

Get encrypted message

![Pasted image 20240311203252](https://github.com/dbissell6/DFIR/assets/50979196/a0415e81-dda0-4bb2-af58-1be960aa0f62)

![Pasted image 20240311202745](https://github.com/dbissell6/DFIR/assets/50979196/1d71741c-640b-4a63-8d52-20cddc10010f)

![Pasted image 20240311204032](https://github.com/dbissell6/DFIR/assets/50979196/3b8529df-4a5a-4a83-94fd-244281aa91ed)

## Phreaky - medium 

<details>
<summary> Python code </summary>

```

     
```

</details>

<details>
<summary> Python code </summary>

```

     
```

</details>

## Data seige - medium

Given pcap

Started by running strings on pcap. 2 things stand out AQacaZ.exe and the base64 commands

![Pasted image 20240309085332](https://github.com/dbissell6/DFIR/assets/50979196/68e9eaa4-34ea-49cb-bb46-07eee4d4e0f8)

In the Base64 commands were a powershell command holding the 3rd part of the flag.

![Pasted image 20240309085421](https://github.com/dbissell6/DFIR/assets/50979196/4da50832-fb08-4228-8790-6912ef1918a6)

Taking the exe to dnspy (dotnet .net)we find the binary uses encryption to transfer data. EZRAT. rfc2898DeriveBytes.

![image](https://github.com/dbissell6/DFIR/assets/50979196/967e6cdf-f5b8-4b3e-8f3b-c026b06b1f8b)


The key can be found in constantes

![Pasted image 20240309092218](https://github.com/dbissell6/DFIR/assets/50979196/d2a4548c-7b1d-4b85-b917-96b5693bad9e)


Plan is to take the function the decrypts in the exe and insert those base64 commands into it

![image](https://github.com/dbissell6/DFIR/assets/50979196/d343f38b-9915-4270-b9e4-3ab341e9ed09)

tshark to extract stream of base64s

![image](https://github.com/dbissell6/DFIR/assets/50979196/685559b6-4b13-46e9-8137-3efcacdd1e4b)

```
tshark -r capture.pcap -q -z follow,tcp,ascii,5 | sed 's/\./§/g' > output.txt
```

note: for whatever reason we see . in the base64. Stole this code, had to convert to special character(added file output read instead of the strings). also had to strip out first couple lines of output file. https://github.com/D13David/ctf-writeups/blob/main/cyber_apocalypse24/forensics/data_siege/decrypt.cs

Find first part of flag

![image](https://github.com/dbissell6/DFIR/assets/50979196/c66afc50-ac3e-4069-96c7-adafc111c4d1)


Find second part of flag

![image](https://github.com/dbissell6/DFIR/assets/50979196/a369aa5c-18b8-4c83-a81a-19b56190517b)


<details>
<summary> Program.cs </summary>

```
using System.Security.Cryptography;
using System.Text;
using System.IO;

static string Decrypt(string cipherText)
{
    string result;
    try
    {
        string encryptKey = "VYAemVeO3zUDTL6N62kVA";
        byte[] array = Convert.FromBase64String(cipherText);
        using (Aes aes = Aes.Create())
        {
            Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[]
            {
                        86,
                        101,
                        114,
                        121,
                        95,
                        83,
                        51,
                        99,
                        114,
                        51,
                        116,
                        95,
                        83
            });
            aes.Key = rfc2898DeriveBytes.GetBytes(32);
            aes.IV = rfc2898DeriveBytes.GetBytes(16);
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(array, 0, array.Length);
                    cryptoStream.Close();
                }
                cipherText = Encoding.Default.GetString(memoryStream.ToArray());
            }
        }
        result = cipherText;
    }
    catch (Exception ex)
    {
        Console.WriteLine(ex.Message);
        Console.WriteLine("Cipher Text: " + cipherText);
        result = "error";
    }
    return result;
}

static string[] GetCommands(string rawData)
{
    List<string> list = new List<string>();
    int num = 0;
    for (int i = 0; i < rawData.Length; i++)
    {
        char c = rawData[i];
        bool flag = c == '§';
        if (flag)
        {
            int num2 = int.Parse(rawData.Substring(num, i - num));
            string item = rawData.Substring(i + 1, num2);
            i += 1 + num2;
            num = i;
            list.Add(item);
        }
    }
    return list.ToArray();
}

// Read the lines from the output file
string[] messages;
try
{
    messages = File.ReadAllLines("output.txt"); // Make sure this is the correct path to your output file
}
catch (IOException ex)
{
    Console.WriteLine("An IO exception occurred while reading the file: " + ex.Message);
    return;
}
catch (Exception ex)
{
    Console.WriteLine("An exception occurred: " + ex.Message);
    return;
}

bool downloadFile = false;


foreach (string message in messages)
{
    if (downloadFile)
    {
        downloadFile = false;
    }

    if (message.Contains("§"))
    {
        Console.Write("\n>>> ");
        foreach (string msg in GetCommands(message))
        {
            string cmd = Decrypt(msg);
            Console.WriteLine(cmd);
            if (cmd.StartsWith("upfile"))
            {
                downloadFile = true;
            }
        }
    }
    else
    {
        Console.Write("\n<<< ");
        Console.WriteLine(Decrypt(message));
    }
}
                 
```

</details>


## Containment - hard

Given .ad1

Use ftkimager to open it. UlTIMATUM.hta shows ransom note. encrypted extentions is .korp.

![Pasted image 20240309225450](https://github.com/dbissell6/DFIR/assets/50979196/8f6d3fc8-dbd4-4fba-b6c5-63abfd952c27)

Find a sus .bat

![Pasted image 20240309230640](https://github.com/dbissell6/DFIR/assets/50979196/ebdbebba-8277-49f0-b4e5-d2eeadb4d483)


Start of powershell commands

![Pasted image 20240309232143](https://github.com/dbissell6/DFIR/assets/50979196/ce9bb33b-98f2-4262-aec7-eb76cb751e1a)

sus execution of intel.exe

![Pasted image 20240309232239](https://github.com/dbissell6/DFIR/assets/50979196/8ae07657-989d-44d6-86f5-e763ab9514ef)

Here is the issue, the exe was deleted, i spent a while trying to recover it. The challenge name 'containment', maybe defender quarentined it? Looking at the logs there is also some evidence this is the case, becsaue commands were ran, then after scripts that turn off denfender were used, then the same command ran again.

![Pasted image 20240310001519](https://github.com/dbissell6/DFIR/assets/50979196/d3102569-ab75-48ce-b81b-e96816e44e45)


When Dfender quarentines its encryptes the file and stores it

```
C:\ProgramData\Microsoft\Windows Defender\Quarantine\entries
```


convert the file back

![image](https://github.com/dbissell6/DFIR/assets/50979196/aa511ac3-b0d4-4a06-9afd-60b6dcc6324e)


# Reversing 

## Packed Away

![Pasted image 20240309124658](https://github.com/dbissell6/DFIR/assets/50979196/b01d0c09-e5cc-4929-9ef9-2155b047fb75)

![Pasted image 20240309124638](https://github.com/dbissell6/DFIR/assets/50979196/2ffc64ae-b932-433d-854b-8a03a6005a4e)

![Pasted image 20240309124623](https://github.com/dbissell6/DFIR/assets/50979196/d0ca7bf1-7721-4b7d-b5d5-388e3f8e51a2)

## Boxcutter

![Pasted image 20240309123916](https://github.com/dbissell6/DFIR/assets/50979196/023f8d40-6027-47eb-99c8-67726de4ae2f)

Can see with ltrace 

![Pasted image 20240309123858](https://github.com/dbissell6/DFIR/assets/50979196/d53ce4dc-9878-40d6-9678-6df2ac0df500)

or in gdb

![Pasted image 20240309123833](https://github.com/dbissell6/DFIR/assets/50979196/85d9e326-b299-4c93-9d2e-73a698868f15)
