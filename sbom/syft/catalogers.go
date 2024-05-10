package syft

// catalogers per scanType
var (
	base = []string{
		"alpm-db-cataloger",
		"apk-db-cataloger",
		"dpkg-db-cataloger",
		"rpm-archive-cataloger",
		"rpm-db-cataloger",
		"linux-kernel-cataloger",
	}
	ruby = []string{
		"ruby-gemfile-cataloger",
		"ruby-gemspec-cataloger",
		"ruby-installed-gemspec-cataloger",
	}
	python = []string{
		"python-package-cataloger",
		"python-installed-package-cataloger",
	}
	javascript = []string{
		"javascript-lock-cataloger",
		"javascript-package-cataloger",
	}
	php = []string{
		"php-composer-installed-cataloger",
		"php-composer-lock-cataloger",
		"php-pecl-serialized-cataloger",
	}
	golang = []string{
		"go-module-file-cataloger",
	}
	golangBin = []string{
		"go-module-binary-cataloger",
	}
	java = []string{
		"java-archive-cataloger",
		"java-gradle-lockfile-cataloger",
		"java-pom-cataloger",
		"graalvm-native-image-cataloger",
	}
	rust = []string{
		"rust-cargo-lock-cataloger",
	}
	rustBin = []string{
		"cargo-auditable-binary-cataloger",
	}
	dotnet = []string{
		"dotnet-deps-cataloger",
	}
	dotnetBin = []string{
		"dotnet-portable-executable-cataloger",
	}
)
