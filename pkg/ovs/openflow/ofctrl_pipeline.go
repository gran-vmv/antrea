// Copyright 2021 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openflow

import "sort"

var pipelineCache = make(map[PipelineID]*ofPipeline)

type ofPipeline struct {
	pipelineID PipelineID
	tableMap   map[StageID][]Table
	firstTable Table
	lastTable  Table
}

func (p *ofPipeline) GetFirstTableInStage(id StageID) Table {
	tables, ok := p.tableMap[id]
	if ok {
		return tables[0]
	}
	return nil
}

func (p *ofPipeline) GetFirstTable() Table {
	return p.firstTable
}

func (p *ofPipeline) IsLastTable(t Table) bool {
	return t.GetID() == p.lastTable.GetID()
}

func (p *ofPipeline) ListAllTables() []Table {
	tables := make([]Table, 0)
	for _, t := range p.tableMap {
		tables = append(tables, t...)
	}
	sort.Slice(tables, func(i, j int) bool {
		return tables[i].GetID() < tables[j].GetID()
	})
	return tables
}

func NewPipeline(id PipelineID, ofTables []Table) Pipeline {
	tableMap := make(map[StageID][]Table)
	for _, t := range ofTables {
		sid := t.GetStageID()
		tableMap[sid] = append(tableMap[sid], t)
	}
	p := &ofPipeline{pipelineID: id,
		tableMap:   tableMap,
		firstTable: ofTables[0],
		lastTable:  ofTables[len(ofTables)-1],
	}
	pipelineCache[id] = p
	return p
}
