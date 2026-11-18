package dnsjournal

// The audit sink: the directory and the file the resolver appends to.
//
// Why it is prepared. The resolver opens its audit file itself, so what is
// at that path is under this feature's control and must be nothing but a
// regular file in an existing directory BEFORE the resolver (re)starts. A
// special file there (a FIFO, a socket, a device, a symbolic link) has no
// legitimate use, and what the resolver does with one is not something to
// depend on: an early manual experiment with a FIFO (2026-11-15) was
// inconclusive, and the scripted check (deploy/verify-smartdns.sh
// --audit-check, same day, SmartDNS 1.2026.11.09-1240, on a real gateway
// and on a workstation) found that the resolver kept answering with a FIFO
// at the path. The regular-file rule stays as a precaution, not because a
// stall was shown.
// PrepareSink makes it so (the reader's unit runs it in ExecStartPre and
// again at start); CheckSink is the host agent's own look, without changing
// anything, right before it restarts the resolver with a config that
// enables the audit: a sink that is not exactly this refuses the restart.
//
// Modes. The file is prepared 0600. The observed resolver sets its audit
// file to 0640 (root:root) whenever it opens it — at start and for the new
// file after each rotation — and leaves the mode alone otherwise; the
// reader sets every regular file of the directory back to 0600 on each
// pass. What keeps other local users out at every moment is the directory:
// 0700, root's.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func ownerOf(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// PrepareSink makes dir a directory of mode 0700 and dir/AuditBase a regular
// file of mode 0600, both owned by the caller. A directory path that exists
// as anything else (a symbolic link included) is an error and is left
// alone. An audit path that is not a regular file (a FIFO, a socket, a
// device, a symbolic link) is removed and replaced by an empty regular
// file: the directory is ours and root-only, nothing else belongs there. An
// existing regular file keeps its content.
func PrepareSink(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fmt.Errorf("audit directory %q is not a clean absolute path", dir)
	}
	fi, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s exists and is not a directory (%s): refusing to use it", dir, fi.Mode().Type())
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	p := filepath.Join(dir, AuditBase)
	fi, err = os.Lstat(p)
	switch {
	case err == nil && fi.Mode().IsRegular():
		return os.Chmod(p, 0o600)
	case err == nil && fi.IsDir():
		return fmt.Errorf("%s is a directory: refusing to use it as the audit file", p)
	case err == nil:
		// A special file: never something the resolver may open.
		if err := os.Remove(p); err != nil {
			return err
		}
	case !os.IsNotExist(err):
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// SinkState is what CheckSink found.
type SinkState struct {
	OK bool `json:"ok"`
	// Dir and File are the modes found ("" absent), e.g. "drwx------".
	Dir   string `json:"dir,omitempty"`
	File  string `json:"file,omitempty"`
	Error string `json:"error,omitempty"`
}

// CheckSink reports whether dir is a real directory of mode 0700 and
// dir/AuditBase a regular file of mode 0600, both owned by uid (the
// resolver container's root and this host's root are the same uid). It
// follows no symbolic link and changes nothing.
func CheckSink(dir string, uid uint32) SinkState {
	var st SinkState
	fail := func(err error) SinkState {
		st.Error = err.Error()
		return st
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fail(errors.New("审计目录不存在"))
		}
		return fail(errors.New("审计目录读不到"))
	}
	st.Dir = fi.Mode().String()
	if !fi.IsDir() {
		return fail(errors.New("审计目录不是普通目录"))
	}
	if fi.Mode().Perm() != 0o700 {
		return fail(fmt.Errorf("审计目录的权限是 %04o，不是 0700", fi.Mode().Perm()))
	}
	if o, ok := ownerOf(fi); ok && o != uid {
		return fail(fmt.Errorf("审计目录属于 uid %d，不是 %d", o, uid))
	}
	fi, err = os.Lstat(filepath.Join(dir, AuditBase))
	if err != nil {
		if os.IsNotExist(err) {
			return fail(errors.New("审计文件不存在（解析器启动前必须已有一个普通文件）"))
		}
		return fail(errors.New("审计文件读不到"))
	}
	st.File = fi.Mode().String()
	if !fi.Mode().IsRegular() {
		return fail(errors.New("审计文件不是普通文件（这里只允许普通文件：FIFO、套接字、设备或符号链接没有正当用途，解析器遇到它们时的行为不可依赖）"))
	}
	if fi.Mode().Perm() != 0o600 {
		return fail(fmt.Errorf("审计文件的权限是 %04o，不是 0600", fi.Mode().Perm()))
	}
	if o, ok := ownerOf(fi); ok && o != uid {
		return fail(fmt.Errorf("审计文件属于 uid %d，不是 %d", o, uid))
	}
	st.OK = true
	return st
}

// DataUsage counts the regular files in the raw and journal directories.
func DataUsage(rawDir, journalDir string) (files int, size int64) {
	for _, dir := range []string{rawDir, journalDir} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if fi, err := os.Lstat(filepath.Join(dir, e.Name())); err == nil && fi.Mode().IsRegular() {
				files++
				size += fi.Size()
			}
		}
	}
	return files, size
}

// purgeSegments deletes, from a journal directory nothing has open, the
// segment files, temporary files and the clear mark; what could not be
// deleted goes into res.Residual and errs. Segments that are left are named
// in the clear mark, so a reader started later knows them as residue.
func purgeSegments(dir string, fault Fault, errs *clearErrs, res *ClearResult) {
	ents, err := fault.readDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			errs.add(PartJournal, "readdir", err)
			res.left().Unknown = true
		}
		return
	}
	var stuck []string
	var next uint64
	for _, e := range ents {
		n := e.Name()
		seg := segNameRe.MatchString(n)
		if !seg && filepath.Ext(n) != ".tmp" {
			continue
		}
		p := filepath.Join(dir, n)
		fi, err := fault.lstat(p)
		if err != nil {
			if !os.IsNotExist(err) {
				errs.add(PartJournal, "lstat", err)
				r := res.left()
				r.Unknown = true
				if seg {
					r.Segments++
					stuck = append(stuck, n)
				}
			}
			continue
		}
		if fi.IsDir() {
			continue
		}
		var size int64
		if fi.Mode().IsRegular() {
			size = fi.Size()
		}
		if err := fault.remove(p); err != nil && !os.IsNotExist(err) {
			errs.add(PartJournal, "remove", err)
			r := res.left()
			r.Bytes += size
			if seg {
				r.Segments++
				stuck = append(stuck, n)
				if sg, _, maxID, err := scanSegment(p, false); err == nil {
					r.Records += sg.count
					next = max(next, maxID+1)
				}
			}
			continue
		}
		res.PurgedFiles++
		res.PurgedBytes += size
	}
	if len(stuck) > 0 {
		if err := fault.fail("write", clearMarkFile); err != nil {
			errs.add(PartJournal, "write", err)
		} else if err := writeClearMark(dir, clearMark{At: time.Now().UTC(), Next: next, Segments: stuck}); err != nil {
			errs.add(PartJournal, "write", err)
		}
		return
	}
	purgeFile(filepath.Join(dir, clearMarkFile), fault, errs, res)
}

// purgeFile deletes one file of the journal directory that holds no
// record (the position, the clear mark).
func purgeFile(p string, fault Fault, errs *clearErrs, res *ClearResult) {
	fi, err := os.Lstat(p)
	if err != nil || fi.IsDir() {
		return
	}
	if err := fault.remove(p); err != nil && !os.IsNotExist(err) {
		errs.add(PartJournal, "remove", err)
		return
	}
	res.PurgedFiles++
	if fi.Mode().IsRegular() {
		res.PurgedBytes += fi.Size()
	}
}

// PurgeData deletes the feature's data from the two fixed directories: the
// host agent's direct clear, used only while no reader runs (after the
// install that turned the journal off, or when the reader is stopped). It
// removes every entry of the raw directory that is not a directory (the
// audit file, its rotated copies, anything special) and, from the journal
// directory, the segment files, the saved position, the clear mark and
// temporary files. With keepAudit (the installed resolver config still
// enables the audit: the resolver may have the file open) the audit file is
// truncated instead of removed, so it stays the regular file the resolver
// expects. The directories themselves stay (the raw one is a container
// mount).
//
// The result says whether everything went (Complete), and if not what is
// left and why: a directory that cannot be listed, a file that cannot be
// looked at, deleted or truncated is an error, never passed over. What is
// left stays known to a reader that starts later: segments are named in
// the clear mark, and while something is left in the raw directory the
// position file is replaced by one that says so and makes the reader follow
// an audit file that could not be emptied from where it ends now — its
// content is not ingested. fault is nil outside tests.
func PurgeData(rawDir, journalDir string, keepAudit bool, fault Fault) ClearResult {
	var res ClearResult
	var errs clearErrs
	rawLeft := false
	ents, err := fault.readDir(rawDir)
	if err != nil && !os.IsNotExist(err) {
		errs.add(PartRaw, "readdir", err)
		res.left().Unknown = true
		rawLeft = true
	}
	for _, e := range ents {
		p := filepath.Join(rawDir, e.Name())
		fi, err := fault.lstat(p)
		if err != nil {
			if !os.IsNotExist(err) {
				errs.add(PartRaw, "lstat", err)
				r := res.left()
				r.Unknown = true
				r.RawFiles++
				rawLeft = true
			}
			continue
		}
		if fi.IsDir() {
			continue
		}
		var size int64
		if fi.Mode().IsRegular() {
			size = fi.Size()
		}
		audit := e.Name() == AuditBase && fi.Mode().IsRegular()
		op := "remove"
		if keepAudit && audit {
			if size == 0 {
				continue
			}
			op, err = "truncate", fault.truncate(p)
		} else {
			err = fault.remove(p)
		}
		if err != nil && !os.IsNotExist(err) {
			errs.add(PartRaw, op, err)
			r := res.left()
			r.RawFiles++
			r.RawBytes += size
			rawLeft = true
			continue
		}
		res.PurgedFiles++
		res.PurgedBytes += size
		res.RawBytes += size
	}
	purgeSegments(journalDir, fault, &errs, &res)
	pos := filepath.Join(journalDir, positionFile)
	if rawLeft {
		// Whatever the audit file still holds (it could not be emptied, or
		// not even be looked at) is not for a later reader to ingest.
		p := position{ClearMS: time.Now().UnixMilli()}
		if fi, err := os.Lstat(filepath.Join(rawDir, AuditBase)); err == nil && fi.Mode().IsRegular() && fi.Size() > 0 {
			p.Ino, p.Offset, p.ClearIno, p.ClearOff = inoOf(fi), fi.Size(), inoOf(fi), fi.Size()
		}
		_ = writePosition(pos, p) // best effort
	} else {
		purgeFile(pos, fault, &errs, &res)
	}
	res.Errors = errs.list()
	res.Complete = len(res.Errors) == 0 && res.Residual == nil
	return res
}
