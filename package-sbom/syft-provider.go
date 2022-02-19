package package_sbom

import (
	"fmt"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/deb"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/rpmdb"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/deepfence/package-scanner/output"
	"github.com/deepfence/package-scanner/util"
	"strings"
)

var (
	errDoesNotProvide = fmt.Errorf("cannot provide packages from the given source")
	linuxExcludeDirs  = []string{"./var/lib/docker/**", "./var/lib/containerd/**", "./mnt/**", "./run/**", "./proc/**", "./dev/**", "./boot/**", "./etc/**", "./sys/**", "./lost+found/**"}
	imageExcludeDirs  = []string{"/mnt", "/run", "/proc", "/dev", "/boot", "/etc", "/sys", "/lost+found"}
)

func GenerateSBOM(config util.Config) (*util.Sbom, error) {
	var exclusions []string
	if strings.HasPrefix(config.Source, "dir:") || config.Source == "." {
		exclusions = linuxExcludeDirs
	} else {
		exclusions = imageExcludeDirs
	}

	catalogerConfig := cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   true,
			IncludeUnindexedArchives: false,
			Scope:                    syftSource.AllLayersScope,
		},
	}
	catalogers := []cataloger.Cataloger{
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		javascript.NewJavascriptLockCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpmdb.NewRpmdbCataloger(),
		java.NewJavaCataloger(catalogerConfig.Java()),
		apkdb.NewApkdbCataloger(),
		//golang.NewGoModuleBinaryCataloger(),
		golang.NewGoModFileCataloger(),
		rust.NewCargoLockCataloger(),
	}

	var auth = make([]image.RegistryCredentials, 0)
	if config.RegistryId != "" && config.NodeType == util.NodeTypeImage {
		// TODO: registry
	}
	registryOptions := &image.RegistryOptions{
		InsecureSkipTLSVerify: true,
		InsecureUseHTTP:       true,
		Credentials:           auth,
	}

	var publisher *output.Publisher
	var err error

	if config.VulnerabilityScan == true {
		publisher, err = output.NewPublisher(config)
		if err != nil {
			return nil, err
		}
		publisher.PublishScanStatus()
	}

	sbom, err := syftProvider(config.Source, exclusions, catalogerConfig, catalogers, registryOptions)
	if err != nil {
		if config.VulnerabilityScan == true {
			publisher.PublishScanError(err.Error())
		}
		return nil, err
	}

	if config.VulnerabilityScan == true {
		publisher.StopPublishScanStatus()
		// Send sbom to Deepfence Management Console for Vulnerability Scan
		publisher.RunVulnerabilityScan(sbom)
		if config.Quiet == false {
			publisher.Output()
		}
	}

	return sbom, nil
}

func syftProvider(source string, exclusions []string, config cataloger.Config, catalogers []cataloger.Cataloger, registryOptions *image.RegistryOptions) (*util.Sbom, error) {
	if config.Search.Scope == "" {
		return nil, errDoesNotProvide
	}
	src, cleanup, err := syftSource.New(source, registryOptions, exclusions)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	resolver, err := src.FileResolver(syftSource.AllLayersScope)
	if err != nil {
		return nil, err
	}
	release := linux.IdentifyRelease(resolver)
	catalog, _, err := cataloger.Catalog(resolver, release, catalogers...)
	if err != nil {
		return nil, err
	}
	return &util.Sbom{
		Packages: grypePkg.FromCatalog(catalog),
		Context: grypePkg.Context{
			Source: &src.Metadata,
			Distro: release,
		},
	}, nil
}
