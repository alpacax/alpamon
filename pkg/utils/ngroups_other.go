//go:build !darwin

package utils

// maxSupplementaryGroups returns 0 (no cap) on platforms other than darwin;
// Linux keeps a much larger setgroups(2) limit that these lists never approach.
func maxSupplementaryGroups() int {
	return 0
}
