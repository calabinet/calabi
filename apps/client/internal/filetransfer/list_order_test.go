package filetransfer

import (
	"reflect"
	"testing"
)

func TestWorkspaceListsKeepOrderAcrossProgressUpdates(t *testing.T) {
	w := &Workspace{
		sources: map[string]StagedFile{
			"z": {ID: "z", Name: "中文.txt"},
			"b": {ID: "b", Name: "same.txt"},
			"a": {ID: "a", Name: "same.txt"},
			"c": {ID: "c", Name: "first.txt"},
		},
		jobs: map[string]*outgoingJob{
			"c": {record: outgoingRecord{Job: Job{ID: "c", State: "sending"}}},
			"a": {record: outgoingRecord{Job: Job{ID: "a", State: "completed"}}},
			"b": {record: outgoingRecord{Job: Job{ID: "b", State: "paused"}}},
		},
	}
	for poll := 0; poll < 64; poll++ {
		w.jobs["c"].record.Job.Progress.Transfer.Offset = int64(poll)
		if poll == 32 {
			w.jobs["a"].record.Job.State = "sending"
		}
		var sources, jobs []string
		for _, s := range w.Staged() {
			sources = append(sources, s.ID)
		}
		for _, j := range w.Jobs() {
			jobs = append(jobs, j.ID)
		}
		if !reflect.DeepEqual(sources, []string{"c", "a", "b", "z"}) {
			t.Fatalf("source poll %d: %v", poll, sources)
		}
		if !reflect.DeepEqual(jobs, []string{"a", "b", "c"}) {
			t.Fatalf("job poll %d: %v", poll, jobs)
		}
	}
}

func TestIncomingListsKeepPeersBatchesAndDuplicateNamesStable(t *testing.T) {
	makeReceiver := func() *Receiver {
		r := &Receiver{sessions: map[string]*receiveSession{}}
		for _, tr := range []Transfer{
			{ID: "d", Batch: "second", Name: "first.txt", State: "waiting"},
			{ID: "c", Batch: "first", Name: "same.txt", State: "completed"},
			{ID: "b", Batch: "first", Name: "same.txt", State: "waiting"},
			{ID: "a", Batch: "first", Name: "first.txt", State: "receiving"},
		} {
			s := &receiveSession{Transfer: tr}
			s.publish()
			r.sessions[tr.ID] = s
		}
		return r
	}
	r := makeReceiver()
	a := &Agent{receivers: map[string]*agentReceiver{
		"peer-z": {grant: Grant{DeviceKey: "peer-z"}, receiver: makeReceiver()},
		"peer-a": {grant: Grant{DeviceKey: "peer-a"}, receiver: r},
	}}
	for poll := 0; poll < 64; poll++ {
		r.sessions["a"].Transfer.Offset = int64(poll)
		if poll == 32 {
			r.sessions["a"].Transfer.State = "completed"
		}
		r.sessions["a"].publish()
		var local, combined []string
		for _, tr := range r.List() {
			local = append(local, tr.ID)
		}
		for _, row := range a.List() {
			combined = append(combined, row.DeviceKey+"/"+row.Transfer.ID)
		}
		if !reflect.DeepEqual(local, []string{"a", "b", "c", "d"}) {
			t.Fatalf("receiver poll %d: %v", poll, local)
		}
		want := []string{"peer-a/a", "peer-a/b", "peer-a/c", "peer-a/d", "peer-z/a", "peer-z/b", "peer-z/c", "peer-z/d"}
		if !reflect.DeepEqual(combined, want) {
			t.Fatalf("agent poll %d: %v", poll, combined)
		}
	}
}
