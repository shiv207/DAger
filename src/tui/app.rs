use super::chat::ChatState;
use crate::models::{PackageNode, RiskAssessment};
use crate::pipeline::PipelineOutput;
use crate::remediation::ProposedFix;
use petgraph::graph::DiGraph;
use std::collections::HashSet;

#[derive(Default)]
pub struct App {
    pub log: Vec<String>,
    pub assessments: Vec<RiskAssessment>,
    pub total_found: usize,
    pub selected: usize,
    pub fix_prompt: Option<ProposedFix>,
    pub fix_in_flight: bool,
    pub graph: DiGraph<PackageNode, ()>,
    pub vulnerable_names: HashSet<String>,
    pub reachable_vulnerable_names: HashSet<String>,
    pub chat: ChatState,
}

impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_log(&mut self, line: &str) {
        self.log.push(line.to_string());
    }

    pub fn load_output(&mut self, output: PipelineOutput) {
        self.total_found = output.total_vulns_found;
        self.vulnerable_names = output
            .assessments
            .iter()
            .map(|a| a.vulnerability.package.name.clone())
            .collect();
        self.reachable_vulnerable_names = output
            .assessments
            .iter()
            .filter(|a| a.reachable)
            .map(|a| a.vulnerability.package.name.clone())
            .collect();
        self.assessments = output.assessments;
        self.graph = output.graph;
    }

    pub fn exploitable_count(&self) -> usize {
        self.assessments.iter().filter(|a| a.reachable).count()
    }

    pub fn selected_assessment(&self) -> Option<&RiskAssessment> {
        self.assessments.get(self.selected)
    }

    pub fn select_next(&mut self) {
        if !self.assessments.is_empty() {
            self.selected = (self.selected + 1).min(self.assessments.len() - 1);
        }
    }

    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }
}
