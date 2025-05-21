<!doctype html>
<html>
<head>
<style>
{styles}
</style>
</head>

<body>
<h1>Algorand Releases</h1>
<p>See <a href="https://developer.algorand.org/">Algorand Developer Resources</a> for instructions on installation and getting started</a></p>
<p>The Algorand public key to verify these files (except RPM<sup><b>**</b></sup>) is at <a href="https://releases.algorand.com/key.pub">https://releases.algorand.com/key.pub</a></p>
<p>The public key for verifying RPMs is <a href="https://releases.algorand.com/rpm/rpm_algorand.pub">https://releases.algorand.com/rpm/rpm_algorand.pub</a></p>
<p>The public key for verifying binaries out of our CI builds is <a href="https://releases.algorand.com/dev_ci_build.pub">https://releases.algorand.com/dev_ci_build.pub</a></p>

<h2>Indexer/Conduit</h2>

Use the CI Build key above to verify these binaries.

<ul>
<li><a href="https://github.com/algorand/conduit/releases/latest">Latest Conduit Release</a></li>
<li><a href="https://github.com/algorand/indexer/releases/latest">Latest Indexer Release</a></li>
</ul>

<hr>

<section id="algod">
<h1>algod</h1>
<h2>stable</h2>
<table><tr><th>File</th><th>Bytes</th><th>GPG Signature</th></tr>
{stable}
</table>

<h2>beta</h2>
<table><tr><th>File</th><th>Bytes</th><th>GPG Signature</th></tr>
{beta}
</table>
</section>

<hr>

</body>
</html>

