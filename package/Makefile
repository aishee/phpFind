BUILDDIR=debian/build
VERSION=1.0

clean:
	rm -Rf ${BUILDDIR}
	rm -f debian/*.log

fetch:
	git clone git@gitlab.aishee.com:packages/phpFind.git

extract: fetch
	mv phpFind ${BUILDDIR}

set_distribution:
		sed -e "s/##version/`cut -d'.' -f1 < /etc/debian_version`/" -i debian/control debian/changelog

package: clean extract set_distribution
	debuild -b -us -uc --lintian-opts -X po-debconf
