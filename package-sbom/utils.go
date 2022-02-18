package package_sbom

type ApkFileRecord struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Digest               *Digest                `json:"digest,omitempty"`
	OwnerGid             string                 `json:"ownerGid,omitempty"`
	OwnerUid             string                 `json:"ownerUid,omitempty"`
	Path                 string                 `json:"path"`
	Permissions          string                 `json:"permissions,omitempty"`
}

// ApkMetadata
type ApkMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Architecture         string                 `json:"architecture"`
	Description          string                 `json:"description"`
	Files                []*ApkFileRecord       `json:"files"`
	GitCommitOfApkPort   string                 `json:"gitCommitOfApkPort"`
	InstalledSize        int                    `json:"installedSize"`
	License              string                 `json:"license"`
	Maintainer           string                 `json:"maintainer"`
	OriginPackage        string                 `json:"originPackage"`
	Package              string                 `json:"package"`
	PullChecksum         string                 `json:"pullChecksum"`
	PullDependencies     string                 `json:"pullDependencies"`
	Size                 int                    `json:"size"`
	Url                  string                 `json:"url"`
	Version              string                 `json:"version"`
}

// CargoPackageMetadata
type CargoPackageMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Checksum             string                 `json:"checksum"`
	Dependencies         []string               `json:"dependencies"`
	Name                 string                 `json:"name"`
	Source               string                 `json:"source"`
	Version              string                 `json:"version"`
}

// Classification
type Classification struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Class                string                 `json:"class"`
	Metadata             *Metadata              `json:"metadata"`
}

// Coordinates
type Coordinates struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	LayerID              string                 `json:"layerID,omitempty"`
	Path                 string                 `json:"path"`
}

// Descriptor
type Descriptor struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Configuration        interface{}            `json:"configuration,omitempty"`
	Name                 string                 `json:"name"`
	Version              string                 `json:"version"`
}

// Digest
type Digest struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Algorithm            string                 `json:"algorithm"`
	Value                string                 `json:"value"`
}

// Document
type Document struct {
	AdditionalProperties  map[string]interface{} `json:"-,omitempty"`
	ArtifactRelationships []*Relationship        `json:"artifactRelationships"`
	Artifacts             []*Package             `json:"artifacts"`
	Descriptor            *Descriptor            `json:"descriptor"`
	Distro                *LinuxRelease          `json:"distro"`
	Files                 []*File                `json:"files,omitempty"`
	Secrets               []*Secrets             `json:"secrets,omitempty"`
	Source                *Source                `json:"source"`
}

// DpkgFileRecord
type DpkgFileRecord struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Digest               *Digest                `json:"digest,omitempty"`
	IsConfigFile         bool                   `json:"isConfigFile"`
	Path                 string                 `json:"path"`
}

// DpkgMetadata
type DpkgMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Architecture         string                 `json:"architecture"`
	Files                []*DpkgFileRecord      `json:"files"`
	InstalledSize        int                    `json:"installedSize"`
	Maintainer           string                 `json:"maintainer"`
	Package              string                 `json:"package"`
	Source               string                 `json:"source"`
	SourceVersion        string                 `json:"sourceVersion"`
	Version              string                 `json:"version"`
}

// ExtraFields
type ExtraFields struct {
}

// File
type File struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Classifications      []*Classification      `json:"classifications,omitempty"`
	Contents             string                 `json:"contents,omitempty"`
	Digests              []*Digest              `json:"digests,omitempty"`
	Id                   string                 `json:"id"`
	Location             *Coordinates           `json:"location"`
	Metadata             *FileMetadataEntry     `json:"metadata,omitempty"`
}

// FileMetadataEntry
type FileMetadataEntry struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	GroupID              int                    `json:"groupID"`
	LinkDestination      string                 `json:"linkDestination,omitempty"`
	MimeType             string                 `json:"mimeType"`
	Mode                 int                    `json:"mode"`
	Type                 string                 `json:"type"`
	UserID               int                    `json:"userID"`
}

// GemMetadata
type GemMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Authors              []string               `json:"authors,omitempty"`
	Files                []string               `json:"files,omitempty"`
	Homepage             string                 `json:"homepage,omitempty"`
	Licenses             []string               `json:"licenses,omitempty"`
	Name                 string                 `json:"name"`
	Version              string                 `json:"version"`
}

// GolangBinMetadata
type GolangBinMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Architecture         string                 `json:"architecture"`
	GoCompiledVersion    string                 `json:"goCompiledVersion"`
	H1Digest             string                 `json:"h1Digest"`
}

// JavaManifest
type JavaManifest struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Main                 *Main                  `json:"main,omitempty"`
	NamedSections        *NamedSections         `json:"namedSections,omitempty"`
}

// JavaMetadata
type JavaMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Manifest             *JavaManifest          `json:"manifest,omitempty"`
	PomProject           *PomProject            `json:"pomProject,omitempty"`
	PomProperties        *PomProperties         `json:"pomProperties,omitempty"`
	VirtualPath          string                 `json:"virtualPath"`
}

// LinuxRelease
type LinuxRelease struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	BugReportURL         string                 `json:"bugReportURL,omitempty"`
	CpeName              string                 `json:"cpeName,omitempty"`
	HomeURL              string                 `json:"homeURL,omitempty"`
	Id                   string                 `json:"id,omitempty"`
	IdLike               []string               `json:"idLike,omitempty"`
	Name                 string                 `json:"name,omitempty"`
	PrettyName           string                 `json:"prettyName,omitempty"`
	PrivacyPolicyURL     string                 `json:"privacyPolicyURL,omitempty"`
	SupportURL           string                 `json:"supportURL,omitempty"`
	Variant              string                 `json:"variant,omitempty"`
	VariantID            string                 `json:"variantID,omitempty"`
	Version              string                 `json:"version,omitempty"`
	VersionID            string                 `json:"versionID,omitempty"`
}

// Main
type Main struct {
}

// Metadata
type Metadata struct {
}

// NamedSections
type NamedSections struct {
}

// NpmPackageJSONMetadata
type NpmPackageJSONMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Author               string                 `json:"author"`
	Description          string                 `json:"description"`
	Files                []string               `json:"files,omitempty"`
	Homepage             string                 `json:"homepage"`
	Licenses             []string               `json:"licenses"`
	Url                  string                 `json:"url"`
}

// Package
type Package struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Cpes                 []string               `json:"cpes"`
	FoundBy              string                 `json:"foundBy"`
	Id                   string                 `json:"id"`
	Language             string                 `json:"language"`
	Licenses             []string               `json:"licenses"`
	Locations            []*Coordinates         `json:"locations"`
	Metadata             interface{}            `json:"metadata,omitempty"`
	MetadataType         string                 `json:"metadataType,omitempty"`
	Name                 string                 `json:"name"`
	Purl                 string                 `json:"purl"`
	Type                 string                 `json:"type"`
	Version              string                 `json:"version"`
}

// PhpComposerAuthors
type PhpComposerAuthors struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Email                string                 `json:"email,omitempty"`
	Homepage             string                 `json:"homepage,omitempty"`
	Name                 string                 `json:"name"`
}

// PhpComposerExternalReference
type PhpComposerExternalReference struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Reference            string                 `json:"reference"`
	Shasum               string                 `json:"shasum,omitempty"`
	Type                 string                 `json:"type"`
	Url                  string                 `json:"url"`
}

// PhpComposerJSONMetadata
type PhpComposerJSONMetadata struct {
	AdditionalProperties map[string]interface{}        `json:"-,omitempty"`
	Authors              []*PhpComposerAuthors         `json:"authors,omitempty"`
	Bin                  []string                      `json:"bin,omitempty"`
	Description          string                        `json:"description,omitempty"`
	Dist                 *PhpComposerExternalReference `json:"dist"`
	Homepage             string                        `json:"homepage,omitempty"`
	Keywords             []string                      `json:"keywords,omitempty"`
	License              []string                      `json:"license,omitempty"`
	Name                 string                        `json:"name"`
	NotificationUrl      string                        `json:"notification-url,omitempty"`
	Provide              *Provide                      `json:"provide,omitempty"`
	Require              *Require                      `json:"require,omitempty"`
	RequireDev           *RequireDev                   `json:"require-dev,omitempty"`
	Source               *PhpComposerExternalReference `json:"source"`
	Suggest              *Suggest                      `json:"suggest,omitempty"`
	Time                 string                        `json:"time,omitempty"`
	Type                 string                        `json:"type,omitempty"`
	Version              string                        `json:"version"`
}

// PomParent
type PomParent struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	ArtifactId           string                 `json:"artifactId"`
	GroupId              string                 `json:"groupId"`
	Version              string                 `json:"version"`
}

// PomProject
type PomProject struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	ArtifactId           string                 `json:"artifactId"`
	Description          string                 `json:"description,omitempty"`
	GroupId              string                 `json:"groupId"`
	Name                 string                 `json:"name"`
	Parent               *PomParent             `json:"parent,omitempty"`
	Path                 string                 `json:"path"`
	Url                  string                 `json:"url,omitempty"`
	Version              string                 `json:"version"`
}

// PomProperties
type PomProperties struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	ArtifactId           string                 `json:"artifactId"`
	ExtraFields          *ExtraFields           `json:"extraFields"`
	GroupId              string                 `json:"groupId"`
	Name                 string                 `json:"name"`
	Path                 string                 `json:"path"`
	Version              string                 `json:"version"`
}

// Provide
type Provide struct {
}

// PythonDirectURLOriginInfo
type PythonDirectURLOriginInfo struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	CommitId             string                 `json:"commitId,omitempty"`
	Url                  string                 `json:"url"`
	Vcs                  string                 `json:"vcs,omitempty"`
}

// PythonFileDigest
type PythonFileDigest struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Algorithm            string                 `json:"algorithm"`
	Value                string                 `json:"value"`
}

// PythonFileRecord
type PythonFileRecord struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Digest               *PythonFileDigest      `json:"digest,omitempty"`
	Path                 string                 `json:"path"`
	Size                 string                 `json:"size,omitempty"`
}

// PythonPackageMetadata
type PythonPackageMetadata struct {
	AdditionalProperties map[string]interface{}     `json:"-,omitempty"`
	Author               string                     `json:"author"`
	AuthorEmail          string                     `json:"authorEmail"`
	DirectUrlOrigin      *PythonDirectURLOriginInfo `json:"directUrlOrigin,omitempty"`
	Files                []*PythonFileRecord        `json:"files,omitempty"`
	License              string                     `json:"license"`
	Name                 string                     `json:"name"`
	Platform             string                     `json:"platform"`
	SitePackagesRootPath string                     `json:"sitePackagesRootPath"`
	TopLevelPackages     []string                   `json:"topLevelPackages,omitempty"`
	Version              string                     `json:"version"`
}

// Relationship
type Relationship struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Child                string                 `json:"child"`
	Metadata             interface{}            `json:"metadata,omitempty"`
	Parent               string                 `json:"parent"`
	Type                 string                 `json:"type"`
}

// Require
type Require struct {
}

// RequireDev
type RequireDev struct {
}

// RpmdbFileRecord
type RpmdbFileRecord struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Digest               *Digest                `json:"digest"`
	Flags                string                 `json:"flags"`
	GroupName            string                 `json:"groupName"`
	Mode                 int                    `json:"mode"`
	Path                 string                 `json:"path"`
	Size                 int                    `json:"size"`
	UserName             string                 `json:"userName"`
}

// RpmdbMetadata
type RpmdbMetadata struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Architecture         string                 `json:"architecture"`
	Epoch                int                    `json:"epoch"`
	Files                []*RpmdbFileRecord     `json:"files"`
	License              string                 `json:"license"`
	Name                 string                 `json:"name"`
	Release              string                 `json:"release"`
	Size                 int                    `json:"size"`
	SourceRpm            string                 `json:"sourceRpm"`
	Vendor               string                 `json:"vendor"`
	Version              string                 `json:"version"`
}

// SearchResult
type SearchResult struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Classification       string                 `json:"classification"`
	Length               int                    `json:"length"`
	LineNumber           int                    `json:"lineNumber"`
	LineOffset           int                    `json:"lineOffset"`
	SeekPosition         int                    `json:"seekPosition"`
	Value                string                 `json:"value,omitempty"`
}

// Secrets
type Secrets struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Location             *Coordinates           `json:"location"`
	Secrets              []*SearchResult        `json:"secrets"`
}

// Source
type Source struct {
	AdditionalProperties map[string]interface{} `json:"-,omitempty"`
	Target               interface{}            `json:"target"`
	Type                 string                 `json:"type"`
}

// Suggest
type Suggest struct {
}
