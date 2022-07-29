package merkle

type Path [][]byte

func (t *merkleTree) InclusionProof(m uint64) Path {
	return t.inclusion(m, t.Node)
}

func (t *merkleTree) inclusion(m uint64, buf [][]byte) Path {
	//fmt.Printf("All: %x\n", buf)
	n := uint64(len(buf))
	p := make(Path, 0)
	if n == 1 && m == 0 {
		return p
	}
	k := largestPowerOf2LessThan(n)
	if m < k {
		p = append(p, t.inclusion(m, buf[0:k])...)
		p = append(p, t.hash(buf[k:n]))
	} else {
		p = append(p, t.inclusion(m-k, buf[k:n])...)
		p = append(p, t.hash(buf[0:k]))
	}
	return p

}

func (t *merkleTree) ConsistencyProof(m uint64) Path {
	return t.consistency(m, t.Node)
}

func (t *merkleTree) consistency(m uint64, buf [][]byte) Path {
	n := uint64(len(buf))
	if 0 < m && m < n {
		return t.subConsistency(m, buf, true)
	}
	return nil
}

func (t *merkleTree) subConsistency(m uint64, buf [][]byte, b bool) Path {
	path := make(Path, 0)
	n := uint64(len(buf))

	if m == n {
		if !b {
			path = append(path, t.hash(buf))
		}
		return path
	}

	if m < n {
		k := largestPowerOf2LessThan(n)

		if m <= k {
			path = append(path, t.subConsistency(m, buf[0:k], b)...)
			path = append(path, t.hash(buf[k:n]))
		} else {
			path = append(path, t.subConsistency(m-k, buf[k:n], false)...)
			path = append(path, t.hash(buf[0:k]))
		}
	}
	return path
}
