package service

import (
	"context"

	"github.com/aegis-vpn/aegis/internal/store"
)

// UsageOverview is the payload shown on the user's consumption page.
type UsageOverview struct {
	Month          string                `json:"month"`
	RxBytes        int64                 `json:"rx_bytes"`
	TxBytes        int64                 `json:"tx_bytes"`
	TotalBytes     int64                 `json:"total_bytes"`
	QuotaBytes     int64                 `json:"quota_bytes"`
	QuotaUsed      float64               `json:"quota_used_percent"`
	RemainingBytes int64                 `json:"remaining_bytes"`
	MaxDevices     int                   `json:"max_devices"`
	DeviceCount    int                   `json:"device_count"`
	ExpiresAt      *int64                `json:"expires_at"`
	Status         string                `json:"status"`
	History        []*store.MonthlyUsage `json:"history"`
	PolicyName     string                `json:"policy_name"`
	UpKbps         int                   `json:"up_kbps"`
	DownKbps       int                   `json:"down_kbps"`
	AutoReactivate bool                  `json:"auto_reactivate"`
}

// GetUsageOverview computes the overview for a user (self or admin-targeted).
func (s *Service) GetUsageOverview(ctx context.Context, actor Actor, userID string) (*UsageOverview, error) {
	if err := actor.requireOwnership(userID); err != nil {
		return nil, err
	}
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	pol, err := s.EffectivePolicy(ctx, u)
	if err != nil {
		return nil, err
	}
	month := store.CurrentMonth(s.Store.Now())
	usage, err := s.Store.GetMonthlyUsage(ctx, u.ID, month)
	if err != nil {
		return nil, err
	}
	history, err := s.Store.ListMonthlyUsage(ctx, u.ID, 12)
	if err != nil {
		return nil, err
	}
	count, err := s.Store.CountActiveDevices(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	quota := s.QuotaFor(u, pol)
	ov := &UsageOverview{
		Month:          month,
		RxBytes:        usage.RxBytes,
		TxBytes:        usage.TxBytes,
		TotalBytes:     usage.TotalBytes,
		QuotaBytes:     quota,
		MaxDevices:     s.MaxDevicesFor(pol),
		DeviceCount:    count,
		ExpiresAt:      s.AccessExpiry(u, pol),
		History:        history,
		PolicyName:     pol.Name,
		UpKbps:         pol.UpKbps,
		DownKbps:       pol.DownKbps,
		AutoReactivate: pol.AutoReactivate,
	}
	if quota > 0 {
		ov.QuotaUsed = float64(usage.TotalBytes) / float64(quota) * 100
		ov.RemainingBytes = quota - usage.TotalBytes
		if ov.RemainingBytes < 0 {
			ov.RemainingBytes = 0
		}
	}
	now := s.Store.Now().Unix()
	ov.Status = string(s.accountState(u, pol, now))
	return ov, nil
}

func (s *Service) accountState(u *store.User, p *store.AccessPolicy, now int64) DeviceState {
	if u.Status == store.UserSuspended {
		return StateSuspended
	}
	if exp := s.AccessExpiry(u, p); exp != nil && now > *exp {
		return StateExpired
	}
	if u.QuotaBytesOverride != nil && *u.QuotaBytesOverride > 0 || (p != nil && p.MonthlyQuotaBytes > 0) {
		month := store.CurrentMonth(s.now())
		if usage, err := s.Store.GetMonthlyUsage(context.Background(), u.ID, month); err == nil {
			if s.QuotaFor(u, p) > 0 && usage.TotalBytes >= s.QuotaFor(u, p) {
				return StateQuotaExceeded
			}
		}
	}
	return StateActive
}
