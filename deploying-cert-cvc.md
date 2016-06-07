How to update cert-cvc from the upstream svn version

Assuming you are in the ejbca folder:

 1. Sync the git repo with the upstream svn repo using `git svn rebase`
 2. `cd cert-cvc`
 3. Find the commit containing the version of cert-cvc that JMRTD is asking for, e.g., using `git log pom.xml`
 4. Checkout that commit, put a tag on it called cert-cvc-$VERSION
 5. Put the following in pom.xml:

	<distributionManagement>
		<repository>
			<id>absolute directory</id>
			<url>file:///$PATH_TO_IRMA/credentials.github.io/repos/maven2</url>
		</repository>
	</distributionManagement>

 6. Run `mvn deploy`
 7. Switch to your credentials.github.io project, commit & push
