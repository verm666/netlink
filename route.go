package netlink

import (
	"fmt"
	"net"
	"strings"
	"syscall"
)

// Scope is an enum representing a route scope.
type Scope uint8

type NextHopFlag int

type Destination interface {
	Family() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
}

type Encap interface {
	Type() int
	Decode([]byte) error
	Encode() ([]byte, error)
	String() string
}

type RouteMetricType int

const (
	RTAX_MTU        RouteMetricType = syscall.RTAX_MTU
	RTAX_WINDOW     RouteMetricType = syscall.RTAX_WINDOW
	RTAX_RTT        RouteMetricType = syscall.RTAX_RTT
	RTAX_RTTVAR     RouteMetricType = syscall.RTAX_RTTVAR
	RTAX_SSTHRESH   RouteMetricType = syscall.RTAX_SSTHRESH
	RTAX_CWND       RouteMetricType = syscall.RTAX_CWND
	RTAX_ADVMSS     RouteMetricType = syscall.RTAX_ADVMSS
	RTAX_REORDERING RouteMetricType = syscall.RTAX_REORDERING
	RTAX_HOPLIMIT   RouteMetricType = syscall.RTAX_HOPLIMIT
	RTAX_INITCWND   RouteMetricType = syscall.RTAX_INITCWND
	RTAX_FEATURES   RouteMetricType = syscall.RTAX_FEATURES
	RTAX_RTO_MIN    RouteMetricType = syscall.RTAX_RTO_MIN
	RTAX_INITRWND   RouteMetricType = syscall.RTAX_INITRWND
	RTAX_CC_ALGO    RouteMetricType = 0x10
	RTAX_QUICKACK   RouteMetricType = 0xf
)

type IntRouteMetric struct {
	Type  RouteMetricType
	Value int
}

type StrRouteMetric struct {
	Type  RouteMetricType
	Value string
}

func NewIntRouteMetric(mx RouteMetricType, value int) *IntRouteMetric {
	return &IntRouteMetric{Type: mx, Value: value}
}

func NewStrRouteMetric(mx RouteMetricType, value string) *StrRouteMetric {
	return &StrRouteMetric{Type: mx, Value: value}
}

var IntRouteMetrics = map[RouteMetricType]struct{}{
	RTAX_MTU:        struct{}{},
	RTAX_WINDOW:     struct{}{},
	RTAX_RTT:        struct{}{},
	RTAX_RTTVAR:     struct{}{},
	RTAX_SSTHRESH:   struct{}{},
	RTAX_CWND:       struct{}{},
	RTAX_ADVMSS:     struct{}{},
	RTAX_REORDERING: struct{}{},
	RTAX_HOPLIMIT:   struct{}{},
	RTAX_INITCWND:   struct{}{},
	RTAX_FEATURES:   struct{}{},
	RTAX_RTO_MIN:    struct{}{},
	RTAX_INITRWND:   struct{}{},
	RTAX_QUICKACK:   struct{}{},
}

var StrRouteMetrics = map[RouteMetricType]struct{}{
	RTAX_CC_ALGO: struct{}{},
}

var RouteMetricNames = map[RouteMetricType]string{
	RTAX_MTU:        "mtu",
	RTAX_WINDOW:     "window",
	RTAX_RTT:        "rtt",
	RTAX_RTTVAR:     "rttvar",
	RTAX_SSTHRESH:   "ssthresh",
	RTAX_CWND:       "cwnd",
	RTAX_ADVMSS:     "advmss",
	RTAX_REORDERING: "reordering",
	RTAX_HOPLIMIT:   "hoplimit",
	RTAX_INITCWND:   "initcwnd",
	RTAX_FEATURES:   "features",
	RTAX_RTO_MIN:    "rto_min",
	RTAX_INITRWND:   "initrwnd",
	RTAX_QUICKACK:   "quickack",
	RTAX_CC_ALGO:    "congctl",
}

// Route represents a netlink route.
type Route struct {
	LinkIndex  int
	ILinkIndex int
	Scope      Scope
	Dst        *net.IPNet
	Src        net.IP
	Gw         net.IP
	MultiPath  []*NexthopInfo
	Protocol   int
	Priority   int
	Table      int
	Type       int
	Tos        int
	Flags      int
	MPLSDst    *int
	NewDst     Destination
	Encap      Encap
	StrMetrics []*StrRouteMetric
	IntMetrics []*IntRouteMetric
}

func (r Route) String() string {
	elems := []string{}
	if len(r.MultiPath) == 0 {
		elems = append(elems, fmt.Sprintf("Ifindex: %d", r.LinkIndex))
	}
	if r.MPLSDst != nil {
		elems = append(elems, fmt.Sprintf("Dst: %d", r.MPLSDst))
	} else {
		elems = append(elems, fmt.Sprintf("Dst: %s", r.Dst))
	}
	if r.NewDst != nil {
		elems = append(elems, fmt.Sprintf("NewDst: %s", r.NewDst))
	}
	if r.Encap != nil {
		elems = append(elems, fmt.Sprintf("Encap: %s", r.Encap))
	}
	elems = append(elems, fmt.Sprintf("Src: %s", r.Src))
	if len(r.MultiPath) > 0 {
		elems = append(elems, fmt.Sprintf("Gw: %s", r.MultiPath))
	} else {
		elems = append(elems, fmt.Sprintf("Gw: %s", r.Gw))
	}
	elems = append(elems, fmt.Sprintf("Flags: %s", r.ListFlags()))
	if len(r.StrMetrics) != 0 || len(r.IntMetrics) != 0 {
		elems = append(elems, fmt.Sprintf("Metrics: %s", r.ListMetrics()))
	}
	elems = append(elems, fmt.Sprintf("Table: %d", r.Table))
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}

func (r *Route) SetFlag(flag NextHopFlag) {
	r.Flags |= int(flag)
}

func (r *Route) ClearFlag(flag NextHopFlag) {
	r.Flags &^= int(flag)
}

type flagString struct {
	f NextHopFlag
	s string
}

// RouteUpdate is sent when a route changes - type is RTM_NEWROUTE or RTM_DELROUTE
type RouteUpdate struct {
	Type uint16
	Route
}

type NexthopInfo struct {
	LinkIndex int
	Hops      int
	Gw        net.IP
	Flags     int
	NewDst    Destination
	Encap     Encap
}

func (n *NexthopInfo) String() string {
	elems := []string{}
	elems = append(elems, fmt.Sprintf("Ifindex: %d", n.LinkIndex))
	if n.NewDst != nil {
		elems = append(elems, fmt.Sprintf("NewDst: %s", n.NewDst))
	}
	if n.Encap != nil {
		elems = append(elems, fmt.Sprintf("Encap: %s", n.Encap))
	}
	elems = append(elems, fmt.Sprintf("Weight: %d", n.Hops+1))
	elems = append(elems, fmt.Sprintf("Gw: %d", n.Gw))
	elems = append(elems, fmt.Sprintf("Flags: %s", n.ListFlags()))
	return fmt.Sprintf("{%s}", strings.Join(elems, " "))
}
