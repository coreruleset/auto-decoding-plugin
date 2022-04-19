# OWASP ModSecurity Core Rule Set - Automatic Decoding Plugin

## Description

This is a plugin that brings the automatic and generic transformation /
decoding of parameters to CRS with the help of ModSec transformations like
`base64DecodeExt`.

Automatic decoding is a way to catch malicious payloads that have
been encoded to bypass the WAF or simply because the backend is known to
decode them before handling. This works by decoding the individual payloads
of a request with built-in transformation functions in the WAF engine.

ModSecurity knows several transformations and the CRS generic transformations
feature makes use of these by transforming / decoding every `ARGS` with
the full series of transformations. If the transforming / decoding changed
the payload (a hint that it was actually encoded), then (and only then)
will the transformed / decoded parameter be examined by CRS.

E.g.: A transformation is the base64 decoding of a parameter:

The base64 string `c3lzdGVtKCdiYXNoJyk=` decodes to `system('bash')`.

`63336c7a644756744b43646959584e6f4a796b3d` is a double encoded string.
It is a hex-encoded version of the aforementioned `c3lzdGVtKCdiYXNoJyk=`.

So a double decoding (hexDecode + base64Decode) will result in
`system('bash')` again.

Simple generic transformations are enabled by default when installing this plugin.

Double generic transformations can be enabled in in the configuration file
auto-decoding-config.conf` in the `plugins` folder.

Generic transformations mean a severe performance impact and should be enabled
with caution. The aforementioned base64 encoded parameter will expand the
number of ARGS from 1 to 1 + 3 parameters (original parameter plus three
decoded parameters). The same parameter at PL4 will bring a whopping 1 + 66
parameters. 

## Trying this out yourself

This new feature allows to detect the following payloads. Use them to test this
plugin.

```
Original payload: system('bash')
Base64 encoded payload: c3lzdGVtKCdiYXNoJyk=
Double-Base64 encoded payload: YzNsemRHVnRLQ2RpWVhOb0p5az0
Base64 and then hex-encoded payload: 63336c7a644756744b43646959584e6f4a796b3d
```

The simple encoding is detected by default after the installation of this
plugin. The double encoded payload detection can be enabled in the
configuration file `auto-decoding-config.conf`.

The rules 933160 (PL1) and 942511 (PL3) will trigger with the following test
requests:

```  
$> curl "http://localhost/?test=c3lzdGVtKCdiYXNoJyk="
$> curl "http://localhost/?test=YzNsemRHVnRLQ2RpWVhOb0p5az0="
$> curl "http://localhost/?test=63336c7a644756744b43646959584e6f4a796b3d"
```

This has been tested on ModSec 2.9.3 as well as ModSec 3.0.4 (nginx connector
1.0.1). Both versions exhibit the identical behavior.


## How to run the generic transformations plugin

Plugins infrastructure was introduced into CRS in early 2021. Older
installations can easily be adopted to run plugins. It's really simple.

### Preparation for older installations

* Create a folder named `plugins` in your existing CRS installation. That
  folder is meant to be on the same level as the `rules` folder. So there is
  your `crs-setup.conf` file and next to it the two folders `rules` and
  `plugins`.
* Update your CRS rules include to follow this pattern:

```
<IfModule security2_module>
	Include modsecurity.d/owasp-modsecurity-crs/crs-setup.conf

  Include modsecurity.d/owasp-modsecurity-crs/plugins/*-config.conf
	Include modsecurity.d/owasp-modsecurity-crs/plugins/*-before.conf

	Include modsecurity.d/owasp-modsecurity-crs/rules/*.conf

	Include modsecurity.d/owasp-modsecurity-crs/plugins/*-after.conf

</IfModule>
```

_Your exact config may look a bit different, namely the paths. The important
part is to accompany the rules includes with three plugin-includes before and
after like above. Adjust the paths accordingly._

### Installation of the plugin

* Copy the files in the incubator plugin `plugins` folder into the CRS plugins
  folder.
* The plugin will be enabled automatically.
* You can disable the plugin conditionally by setting the
  `tx.auto-decoding-plugin_enabled` variable. See the
  `auto-decoding-config.conf` file for details.
* Restart (or reload) the server.

## Performance

This plugin brings a significant performance impact.

Below is a rough estimate of throughput from a local test machine against a local,
midsize server. All values in seconds.

The test was carried out with 100 runs for each scenario with 1000 requests
each. Then the median time to serve the requests was taken for each of the 100
runs and scenarios. Below's numbers are this median value of a run across all
runs for a given scenario.

| URI | PL1 | PL3 | PL4 | PL3 with plugin enabled | PL4 with plugin and double decoding enabled |
| ---------- | ---------- | ---------- | ---------- | ---------- | ---------- |
| http://server/                                                 | 2.6 | 2.7 | 2.6 | 2.9 | 2.8 |
| http://server/?test=system('bash')                             | 2.8 | 3.0 | 3.0 | 3.3 | 4.3 |
| http://server/?test=c3lzdGVtKCdiYXNoJyk=                       | 2.7 | 2.9 | 2.8 | 3.4 | 4.5 |
| http://server/?test=YzNsemRHVnRLQ2RpWVhOb0p5az0=               | 2.7 | 2.9 | 2.8 | 3.5 | 4.2 |
| http://server/?test=63336c7a644756744b43646959584e6f4a796b3d   | 2.6 | 2.9 | 2.7 | 3.3 | 3.8 |

Enabling the generic transformations adds an overhead of roughly 10% regardless
of parameters or not. This is due to the extension of the target list of about
half the rules with a regular expression (in order to apply the transformed
rules).

With encoded parameters in the request, the overhead can become very steep,
namely when enabling double-encoding, where it can add as much 50%.

## Mechanics

The rules in this plugin transform `ARGS` parameters with a series of 
transformations. 

### Mechanics of a simple transformation rule / single decoding rule

Consider this rule:

```
SecRule ARGS "!@streq %{ARGS}" \
   "id:904100,\
   phase:2,\
   pass,\
   t:base64DecodeExt,\
   nolog,\
   setvar:'tx.tf_1_base64DecodeExt_%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
```

The rule transforms any given `ARGS` with the `base64DecodeExt` transformation.
The SecRule condition will then examine the transformed parameter
against the original, non-transformed parameter.

If the two strings are not equal (and only then!), a new `TX` variable is
created. The new variable will have the name `tx.tf_1_base64DecodeExt_ARGS:<varname>`.

The prefix `tf_1_` indicates that it's a simply transformed parameter.

### Mechanics of a double transformation rule / double decoding rule

Consider this rule:

```
SecRule TX:/^tf_1_*/ "!@streq %{MATCHED_VAR_NAME}" \
   "id:904400,\
   phase:2,\
   pass,\
   t:base64DecodeExt,\
   nolog,\
   setvar:'tx.tf_2_base64DecodeExt_%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"
```

The rule transforms any given simply transformed parameter (identified
via the prefix `tf_1_`) with the `base64DecodeExt` transformation
and the SecRule constraint will then examine the transformed parameter
against the original, non-transformed argument (here the simply transformed parameter).

If the two strings are not equal (and only then!), a new `TX` variable is
created. The new variable will have the name 
`tx.tf_2_base64DecodeExt_TX:tf_1_<simple-transformation>_ARGS:<varname>`.

The name of the double transformation is thus a prefixed version of
the simple transformation name.

The prefix `tf_2_` indicates that it's a double transformed parameter.

## Various

This plugin is based on an idea of [@spartantri](https://github.com/spartantri)
and [@dune73](https://github.com/dune73) to decode parameters and expand the
target lists to include the new parameter. We literally had the same idea in
the same week independent of one another. Making this generic and applying it
across the board via a plugin is the logical next step.

