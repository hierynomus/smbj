= smbj - SMB2/SMB3 client library for Java
Jeroen van Erp
:smbj_groupid: com.hierynomus
:smbj_version: 0.11.5
:source-highlighter: pygments

To get started, have a look at one of the examples. Hopefully you will find the API pleasant to work with :)

image:https://github.com/hierynomus/smbj/actions/workflows/gradle.yml/badge.svg["Build SMBJ", link="https://github.com/hierynomus/smbj/actions/workflows/gradle.yml"]
image:https://app.codacy.com/project/badge/Grade/cf3df44c64c84035b58b054b4e219c24["Codacy Grade", link="https://app.codecov.io/gh/hierynomus/smbj"]
image:https://codecov.io/gh/hierynomus/smbj/branch/master/graph/badge.svg["codecov", link="https://codecov.io/gh/hierynomus/smbj"]
image:http://www.javadoc.io/badge/com.hierynomus/smbj.svg?color=blue["JavaDocs", link="http://www.javadoc.io/doc/com.hierynomus/smbj"]
image:https://maven-badges.herokuapp.com/maven-central/com.hierynomus/smbj/badge.svg["Maven Central",link="https://maven-badges.herokuapp.com/maven-central/com.hierynomus/smbj"]

== Getting SMBJ

To get SMBJ, you have two options:

. Add a dependency to SMBJ to your project.
. Build SMBJ yourself.

And, if you want, you can also run the SMBJ examples.

Binary releases of SMBJ are not provided here, but you can download it http://search.maven.org/#artifactdetails%7C{smbj_groupid}%7Csmbj%7C{smbj_version}%7Cjar[straight from the Maven Central repository] if you want to.

== Examples

A - Listing Files on a Share/Folder

```java

    SMBClient client = new SMBClient();

    try (Connection connection = client.connect("SERVERNAME")) {
        AuthenticationContext ac = new AuthenticationContext("USERNAME", "PASSWORD".toCharArray(), "DOMAIN");
        Session session = connection.authenticate(ac);

        // Connect to Share
        try (DiskShare share = (DiskShare) session.connectShare("SHARENAME")) {
            for (FileIdBothDirectoryInformation f : share.list("FOLDER", "*.TXT")) {
                System.out.println("File : " + f.getFileName());
            }
        }
    }

```

B - Deleting a file

```java

    SMBClient client = new SMBClient(config);

    try (Connection connection = client.connect("SERVERNAME")) {
        AuthenticationContext ac = new AuthenticationContext("USERNAME", "PASSWORD".toCharArray(), "DOMAIN");
        Session session = connection.authenticate(ac);

        // Connect to Share
        try (DiskShare share = (DiskShare) session.connectShare("SHARENAME")) {
            share.rm("FILE");
        }
    }

```

C - Adjusting Timeout and Socket Timeout

```java

    SmbConfig config = SmbConfig.builder()
            .withTimeout(120, TimeUnit.SECONDS) // Timeout sets Read, Write, and Transact timeouts (default is 60 seconds)
            .withSoTimeout(180, TimeUnit.SECONDS) // Socket Timeout (default is 0 seconds, blocks forever)
            .build();

    SMBClient client = new SMBClient(config);

    try (Connection connection = client.connect("SERVERNAME")) {
        AuthenticationContext ac = new AuthenticationContext("USERNAME", "PASSWORD".toCharArray(), "DOMAIN");
        Session session = connection.authenticate(ac);

        // Connect to Share
        try (DiskShare share = (DiskShare) session.connectShare("SHARENAME")) {
            ...
        }
    }

```

== Frequently Asked Questions

=== When I run my code I get an `SMBApiException` with the message `STATUS_... (0x...)`. What am I doing wrong?

SMBJ is a low-level SMB client implementation.
Most file/directory operations result in a request being sent to the SMB server.
If the server responds to these requests with an error SMBJ will pass this error back to the calling code via an exception.
The `STATUS_...` value is the error code the server sent back to the client.

It is considered out of scope for the SMBJ project to document each and every possible error condition that may occur when using the SMB protocol.
Detailed information on these errors can be found in the https://msdn.microsoft.com/en-us/library/cc246482.aspx[SMB specification] and the https://msdn.microsoft.com/en-us/library/cc704588.aspx[error code table].
Some common errors are described below.

=== When I try to open a file or directory my code fails with `STATUS_ACCESS_DENIED`. How can I fix this?

This error means that the file access you've requested (the set of `AccessMask` values) is not being allowed by the server for the user account you used to log in to the server.
Why this happens exactly depends on the precise set of `AccessMask` values you specified and the access control list that has been set on the file or directory in question.

To resolve this, reduce the set of `AccessMask` values down to just the access that you need.
For instance, if you only want to read the contents of the file use `FILE_READ_DATA` instead of something more broad like `GENERIC_READ` or `GENERIC_ALL`.

The special `MAXIMUM_ALLOWED` value can be used to ask the server to grant the full set of permissions that are allowed by the access control list.
You can then query the `FileAccessInformation` information class to determine which set of permissions was granted by the server.

For more details please refer to the documentation on https://docs.microsoft.com/en-us/windows/desktop/FileIO/creating-and-opening-files[creating and opening files on MSDN].

=== When I try to open a file or directory my code fails with `STATUS_SHARING_VIOLATION`. What does this mean?

A sharing violation error means that some other process has already opened the file or directory in question in a way that is incompatible with how you're trying to open it.
This could be your own program, a different program running on your machine, a program running on a different client machine or even a process on the SMB server itself like an indexing or virus scanning service.

The SMB protocol does allow multiple clients to open the same file at the same time, but they need to cooperate when doing so.
This is controlled by the set of `SMB2ShareAccess` values that are passed to the open file calls.
When this set is empty, the SMB client requests exclusive access to the file.
Passing one or more values indicates that other clients may open the file for the specified operations as well.
For instance, if you open the file with only `FILE_SHARE_READ` and successfully open the file, then other clients may open the file for reading as well.
If another client tries to open the file for writing, it will fail at that point with `STATUS_SHARING_VIOLATION` as long as you have the file open.

For more details please refer to the documentation on https://docs.microsoft.com/en-us/windows/desktop/FileIO/creating-and-opening-files[creating and opening files on MSDN].

== Depending on SMBJ
If you're building your project using Maven, you can add the following dependency to the `pom.xml`:

[source,xml,subs="verbatim,attributes"]
----
<dependency>
  <groupId>{smbj_groupid}</groupId>
  <artifactId>smbj</artifactId>
  <version>{smbj_version}</version>
</dependency>
----

If your project is built using another build tool that uses the Maven Central repository, translate this dependency into the format used by your build tool.

== Building SMBJ
. Clone the SMBJ repository.
. Ensure you have Java7 installed with the http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html[Unlimited strength Java Cryptography Extensions (JCE)].
. Run the command `./gradlew clean build`.

== Specifications
The implementation is based on the following specifications:

- https://msdn.microsoft.com/en-us/library/cc246482.aspx[[MS-SMB2\]: Server Message Block (SMB) Protocol Versions 2 and 3]
- https://msdn.microsoft.com/en-us/library/cc247021.aspx[[MS-SPNG\]: Simple and Protected GSS-API Negotiation Mechanism (SPNEGO) Extension]
- https://msdn.microsoft.com/en-us/library/cc236621.aspx[[MS-NLMP\]: NT LAN Manager (NTLM) Authentication Protocol]
- https://msdn.microsoft.com/en-us/library/cc230273.aspx[[MS-DTYP\]: Windows Data Types]
- https://msdn.microsoft.com/en-us/library/cc231196.aspx[[MS-ERREF\]: Windows Error Codes]
- https://msdn.microsoft.com/en-us/library/cc231987.aspx[[MS-FSCC\]: File System Control Codes]
- https://msdn.microsoft.com/en-us/library/cc226982.aspx[[MS-DFSC\]: Distributed File System (DFS): Referral Protocol]
