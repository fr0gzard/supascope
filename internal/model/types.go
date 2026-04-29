package model

import "time"

type TargetType string

const (
	TargetURL             TargetType = "url"
	TargetLocalPath       TargetType = "local_path"
	TargetSupabaseProject TargetType = "supabase_project"
)

type Target struct {
	Type  TargetType `json:"type"`
	Value string     `json:"value"`
}

type ServiceStatus string

const (
	ServiceObserved     ServiceStatus = "observed"
	ServiceReachable    ServiceStatus = "reachable"
	ServiceUnauthorized ServiceStatus = "unauthorized"
	ServiceForbidden    ServiceStatus = "forbidden"
	ServiceNotFound     ServiceStatus = "not_found"
	ServiceBlocked      ServiceStatus = "blocked"
	ServiceNotObserved  ServiceStatus = "not_observed"
	ServiceUnknown      ServiceStatus = "unknown"
)

type ServiceMap struct {
	REST      ServiceStatus `json:"rest"`
	Auth      ServiceStatus `json:"auth"`
	Storage   ServiceStatus `json:"storage"`
	Realtime  ServiceStatus `json:"realtime"`
	Functions ServiceStatus `json:"functions"`
	GraphQL   ServiceStatus `json:"graphql"`
}

type Evidence struct {
	Source      string `json:"source"`
	File        string `json:"file,omitempty"`
	URL         string `json:"url,omitempty"`
	Line        int    `json:"line,omitempty"`
	MaskedValue string `json:"masked_value,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
}

type Discovery struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	MaskedValue string    `json:"masked_value,omitempty"`
	Source      string    `json:"source"`
	Evidence    *Evidence `json:"evidence,omitempty"`
}

type Finding struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Evidence       Evidence `json:"evidence"`
	Impact         string   `json:"impact"`
	Recommendation string   `json:"recommendation"`
	Confidence     string   `json:"confidence"`
}

type Options struct {
	Target               Target
	Key                  string
	UserAgent            string
	Headers              map[string]string
	Debug                bool
	MaxAssets            int
	JSON                 bool
	Output               string
	Yes                  bool
	Dynamic              bool
	Interactive          bool
	ActiveChecks         bool
	ActiveStorageTests   bool
	GraphQLIntrospection bool
	GraphQLSchemaOutput  string
	// Pacing controls for active probes
	Delay          time.Duration `json:"delay"`
	MaxConcurrency int           `json:"max_concurrency"`
}

type Report struct {
	Scanner     ScannerInfo `json:"scanner"`
	Target      Target      `json:"target"`
	Mode        []string    `json:"mode"`
	Timestamp   string      `json:"timestamp"`
	Services    ServiceMap  `json:"services"`
	Discoveries []Discovery `json:"discoveries"`
	Findings    []Finding   `json:"findings"`
}

type ScannerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
