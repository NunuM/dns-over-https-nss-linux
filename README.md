### DNS over HTTPS on Linux

This is a library that offers name resolution using [Cloudflare's REST API](https://developers.cloudflare.com/1.1.1.1/dns-over-https) for GLibC based operative systems, DoH for short. In general, every operative system offers some form of DNS name resolution API, for instance, on GLibC you have **gethostbyname**, however, this library goes two steps further, one is the particularity of executing that task over an encrypted channel and the other is that will be the who will provide answers when you call **gethostbyname**.

Nowadays, DNS resolution is done via the user data protocol, which implies plaintext queries that are passive to be leaked to third parties capable of monitor the network. The metadata that is being given by us on the intent of which website we are trying to connect to is privacy and a human right offense that we must fight, and as developers, we have a moral responsibility to not accept this situation and push this lack of privacy to **/dev/null**.

We developers came with two approaches, DNS over TSL (DoT) and DNS over HTTPs traffic (DoH). Both use TLS, one is for encrypts UDP traffic and the other is to encrypt HTTP traffic.

A fast overview of this feature tells that on any distro GNU/Linux with systemd you have DoT, but is disabled by default, on Android DoH was released starting Chrome 80. Apple said that will support DoH and DoT by this fall and Windows 10 also has support for both modes.

I am be focusing on Linux, I won't deny it, it is my favorite. In Linux, we have a special file: **nsswitch.conf** and as [Delorie](https://developers.redhat.com/blog/2018/11/26/etc-nsswitch-conf-non-complexity/) puts out: "that most people ignore, few people understand, but all people generally rely on" and I add, and the documentation for developers is scarce.

This file from the [Name Service Switch](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html) has the information about the services (databases as they put out) and the corresponding libraries. API calls like **gethostbyname** will trigger a lookup upon this file to see which library to handle the request. In this example, and according to the output of **nss file** the call will be handled by the **files** and dns **database**, if **files** do not come with an answer, the next one will be invoked, in this case, **dns**

```bash
# cat /etc/nsswitch.conf

# database      implementation
passwd:         files systemd
group:          files systemd
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
```

Technically, how this delegation is achieved by GLibC? When you call **gethostbyname**, GLibC selects one library based on your nss configuration, the name of the selected will be used to find the shared library **libnss_dns.so**
and then, the target method is prefixed **\_nss_dns_** and a [call](https://www.man7.org/linux/man-pages/man3/dlopen.3.html) is made to the library.

```
# objdump -d `whereis libnss-dns` | grep '_nss_dns_.*:$'
0000000000001160 <_nss_dns_gethostbyname3_r@plt>:
0000000000001220 <_nss_dns_gethostbyname3_r@@GLIBC_PRIVATE-0x12b0>:
00000000000024d0 <_nss_dns_gethostbyname3_r@@GLIBC_PRIVATE>:
0000000000002598 <_nss_dns_gethostbyname2_r@@GLIBC_PRIVATE>:
0000000000002640 <_nss_dns_gethostbyname_r@@GLIBC_PRIVATE>:
0000000000002728 <_nss_dns_gethostbyname4_r@@GLIBC_PRIVATE>:
0000000000002a78 <_nss_dns_gethostbyaddr2_r@@GLIBC_PRIVATE>:
0000000000002e68 <_nss_dns_gethostbyaddr_r@@GLIBC_PRIVATE>:
00000000000033d8 <_nss_dns_getnetbyname_r@@GLIBC_PRIVATE>:
0000000000003558 <_nss_dns_getnetbyaddr_r@@GLIBC_PRIVATE>:
00000000000037f0 <_nss_dns_getcanonname_r@@GLIBC_PRIVATE>:
```  

This way, the developers can add their implementation. For each database, the developer must implement the respective interface. Exists several others libraries like **libnss-mysql**, **libnss-systemd**, etc.

After showing the internals, by now, we know how to make DoH system-wide a reality. We must implement **hosts API** a
make an HTTPs request to CloudFlare's API, and lucky for us, we do not have to implement and make HTTP requests in C since the Rust community is awesome and someone has done the [Rust bindings](https://github.com/csnewman/libnss-rs). The
interface becomes simpler.

````rust
pub trait HostHooks {
    fn get_all_entries() -> Response<Vec<Host>>;

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host>;

    fn get_host_by_addr(addr: IpAddr) -> Response<Host>;
}
````

The method **get_host_by_name** is the one that we are interested in. We receive the name and if it is been requested
IPV4 or IPV6 for that name. Then, we make the [HTTP request](https://github.com/NunuM/dns-over-https-nss-linux/blob/master/ragevpn/src/lib.rs#L56). We have used OpenSSL to encrypt the TPC traffic, on this 
request it's added the SNI extension, and I have parsed the HTTP protocol without using any third-party library.

To install this library, and assuming you already have Rust installed in your machine, open the terminal and type:

```bash
git clone https://github.com/NunuM/dns-over-https-nss-linux.git doh

cd doh/ragevpn

cargo build --release

cd ..

cd target/release
cp libnss_ragevpn.so libnss_ragevpn.so.2
sudo install -m 0644 libnss_ragevpn.so.2 /lib
sudo /sbin/ldconfig -n /lib /usr/lib

# edit nss configuration
sudo nano /etc/nsswitch.conf
#hosts: files ragevpn 
```

Now, your DNS queries will be handled by this library. Note that if you have your browser open, you need to restart it,
since at the time you open your browser the nss configuration was different. 

How do we know that our library is the one making the DNS resolution? Well, you can **ping google.com**, or **strace -o debug ping google.pt** and
examine the output of strace command. You can also [add](https://github.com/NunuM/dns-over-https-nss-linux/blob/master/ragevpn/src/lib.rs#L44)

```rust
// add in line 44 
let mut log = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .read(true)
            .create(true)
            .open("/tmp/resolving")
            .unwrap();

writeln!(log, "{}", name).ok();
// or use syslog to do this, is up to you.
```

To conclude, it is obvious that Cloudflare will know our DNS queries, but this is a choice that I am willing to make, so do you. Besides
that, this knowledge can be useful for service discovery in distributed systems, or blacklisting/whitelist domain names at the local level. I hope that you like this post
and if you see any error, am I open to resolve new issues. 
