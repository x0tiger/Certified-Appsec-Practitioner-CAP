## What is Insecure File Uploads?  

- File upload vulnerability is a common security issue in most web applications that have a file upload feature without any security validation against the uploaded files. 

- This vulnerability can allow attackers to upload a file with malicious code in it which can be executed on the hosting server. 

## Types of Insecure File Uploads

There are several types of insecure file uploads, including:

    Unrestricted File Upload

    Insecure File Extensions

    Insecure Storage

    Unvalidated File Contents
    
 ---
  
## Impact

- Uploading phishing pages to the website. 
- Compromising the hosting server by uploading a shell. 
- Uploading a permanent XSS payload which can compromise users' access.
- injecting files with malicious paths can overwrite existing files as we can upload “.htaccess” file to execute specific files/scripts.

 ## File Upload Exploitation

 RCE through File upload
 
 ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/0.png)

In some web applications, there is no validation for the uploaded files. In this case, the attacker can upload a shell to the server.

#### For example: Uploading shell.php file with the following content:

 ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/1.png)

 After uploading the file, the attacker will go to the path where this file is uploaded then he will send OS commands that will be executed by the server.

 #### e.g: http://example.com/upload/shell.php?cmd=ls -la 

 ### XSS through File Upload 

- Sometimes web applications accept SVG files by which the attacker can inject javascript codes that will be executed when the file is loaded.

- The following XML is an example of a valid SVG file that will execute JS when loaded in the browser:
 ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/2.png)

- After uploading the file.svg and visiting the path of this file, the injected JS code will be executed to the end-user.

### Bypassing Upload Protection 
#### Example 1:

- In some cases, you will not be able to upload files with specific extensions like (.php, JSP, etc)

![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/3.png)

- The above code snippet is an example of a basic protecting technique in which the developer checks if the uploaded file is of extension (php , php3 , phtml , php4). 

- Then, he will return a “Not allowed” message if one of these extensions were found.

- The weakness here is that the code is not using a case-sensitive check which can be bypassed easily by sending the file in upper-case format.

- ##### e.g: shell.PHP

### Example 2: 
![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/4.png)

- The above code snippet is an example of a mime content type verification.
 
- It will check the content type of the uploaded file checking if it is a gif/jpeg image file, and if not it will return a “Not allowed” message.


- This can be easily bypassed by intercepting the HTTP request using Burp Suite and changing the content-type header to the specified extension.

#### For example: Changing this 

![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/5.png)

##### To this:

![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/6.png)

 ### Example 3: 
 ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/7.png)

 - The above code snippet is an example of a case-sensitive verification.

- This technique can be bypassed by uploading .htaccess file.

#### htaccess Trick 

Attackers can upload an htaccess file which can trick the apache server to execute safe extension files.

There are two methods that can be used: 

  - The SetHandler method
  - The AddType method

### SetHandler Method 

- Attackers can upload the following .htaccess file that will trick the apache server to execute any file with name _php.gif as a valid PHP file.
 ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/8.png)

- Then easily the attacker will upload a file _php.gif that contains the malicious code that will be executed by the hosting server.

### The AddType Method

- This method is similar to SetHandler, you can upload the .htaccess file  with the following content:
- 
  ![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/9.png)

  - This apache server will consider any .gif file as a valid php file that can be executed by the hosting server.
 
## Example 4:

![photo](https://github.com/x0tiger/Certified-Appsec-Practitioner-CAP/blob/main/14-Insecure%20File%20Uploads/Images/10.png)

- The above code snippet is an example of image content verification in which it uses the getimagesize() function that will check the size of the image and check if a correct image is provided.

- This technique can be bypassed by injecting php code into the image comment.

### Using exiftool:

`exiftool -Comment='' file.jpg`

#### Then:
`mv file.jpg file.php.jpg`

### Mitigation 


- Instead of using a blacklist, use a whitelist of the acceptable files. 
-  Do not expose the path where the uploaded file is stored.
-  Change the file name to something else generated by the application. 
-  Set a file size limit.
- Validate the file type and do not trust the content-type header.
