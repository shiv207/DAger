use crate::models::RiskAssessment;
use crate::pipeline::PipelineOutput;

#[derive(Default)]
pub struct App {
    pub log: Vec<String>,
    pub assessments: Vec<RiskAssessment>,
    pub total_found: usize,
    pub selected: usize,
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
        self.assessments = output.assessments;
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
