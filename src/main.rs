
use csv::{Writer, WriterBuilder};
use std::fs::File;
use serde::{
    Serialize,
    Deserialize
};

use std::collections::HashMap;
// use serde_json::Result;
use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args{
    /// Input JSON file path
    #[arg(short,long)]
    file: Option<String>,
    ///For debug purpose
    #[arg(short,long, default_value_t = false)]
    debug: bool,
    ///Output CSV file path
    #[arg(short,long)]
    output_path: Option<String>,
    ///Specify the mode sast, sca or secret
    #[arg(short,long)]
    mode: Option<String>,
}
trait CsvWriter{
    /**
     * A trait that is implemented by all the JSON nodes to write its correspoding data into to the csv file.
     */
    fn write_data(&self, writer: &mut Writer<File>, s_no: u64, args: &Args);
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub struct Welcome {
    errors: Vec<Error>,
    interfile_languages_used: Vec<Option<serde_json::Value>>,
    paths: Paths,
    results: Vec<Result>,
    skipped_rules: Vec<Option<serde_json::Value>>,
    version: String,
}

impl CsvWriter for Welcome{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.mode.as_ref().unwrap().as_str() == "sast" {
            for i in &self.results {
                writer.write_field(s_no.to_string()).unwrap();
                i.write_data(writer,s_no,args);
                writer.write_record(None::<&[u8]>).unwrap();
                s_no += 1;
            }
            return;
        }
        self.errors
        .iter()
        .map(|x| x.write_data(writer, s_no, args))
        .collect::<()>();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Error {
    code: i64,
    level: String,
    message: String,
    path: String,
    #[serde(rename = "type")]
    error_type: ErrorType,
    spans: Option<Vec<Span>>,
}

impl CsvWriter for Error{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        writer.write_field(self.code.to_string()).unwrap();
        writer.write_field(self.level.to_string()).unwrap();
        writer.write_field(self.message.to_string()).unwrap();
        writer.write_field(self.path.to_string()).unwrap();
        self.error_type.write_data(writer, s_no, args);
        self.spans.as_ref()
        .iter()
        .map(|x| x.iter().map(|y| y.write_data(writer, s_no, args)).collect::<()>())
        .collect::<()>();
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum ErrorType {
    String(String),
    UnionArray(Vec<TypeTypeUnion>),
}

impl CsvWriter for ErrorType{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self{
            Self::String(x) => {
                writer.write_field(x).unwrap();
            },
            Self::UnionArray(x) => {
                x.iter()
                .map(|y| y.write_data(writer, s_no, args))
                .collect::<()>();
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TypeTypeUnion {
    LocationElementArray(Vec<LocationElement>),
    String(String),
}

impl CsvWriter for TypeTypeUnion{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self {
            Self::LocationElementArray(x) => {
                x.iter()
                .map(|y| y.write_data(writer, s_no, args))
                .collect::<()>();
            },
            Self::String(x) => {
                writer.write_field(x.to_string()).unwrap();
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LocationElement {
    end: End,
    path: String,
    start: End,
}

impl CsvWriter for LocationElement{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        self.end.write_data(writer, s_no, args);
        writer.write_field(self.path.to_string()).unwrap();
        self.start.write_data(writer, s_no, args);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct End {
    col: i64,
    line: i64,
    offset: i64,
}

impl CsvWriter for End{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            writer.write_field(self.line.to_string()).unwrap();
            return;
        }
        writer.write_field(self.col.to_string()).unwrap();
        writer.write_field(self.line.to_string()).unwrap();
        writer.write_field(self.offset.to_string()).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Span {
    end: End,
    file: String,
    start: End,
}

impl CsvWriter for Span{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        self.end.write_data(writer, s_no, args);
        writer.write_field(self.file.to_string()).unwrap();
        self.start.write_data(writer, s_no, args);
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Skipped{
    path: String,
    reason: String,
}

impl CsvWriter for Skipped{
    fn write_data(&self, writer: &mut Writer<File>, s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Policy{
    id: i64,
    name: String,
    slug: String,
}

impl CsvWriter for Policy{
    fn write_data(&self, writer: &mut Writer<File>, s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Rule{
    origin: Option<String>,
    rule_id: String,
    url: String,
    version_id: String,
}

impl CsvWriter for Rule {
    fn write_data(&self, writer: &mut Writer<File>, s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SemgrepDev{
    rule: Rule
}

impl CsvWriter for SemgrepDev{
    fn write_data(&self, writer: &mut Writer<File>, s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Paths {
    scanned: Vec<String>,
    skipped: Option<Vec<Skipped>>,
}

impl CsvWriter for Paths{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Result {
    check_id: serde_json::Value,
    end: End,
    extra: Extra,
    path: String,
    start: End,
}

impl CsvWriter for Result{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.mode.as_ref().unwrap().as_str() == "sast" {
            //self.check_id.write_data(writer, s_no, args);
            if let serde_json::Value::String(x) = &self.check_id {
                writer.write_field(x.to_string()).unwrap();
            }
            self.extra.write_data(writer, s_no, args);
            writer.write_field(self.path.to_string()).unwrap();
            self.start.write_data(writer, s_no, args);
            return;
        }
        //self.check_id.write_data(writer, s_no, args);
        self.end.write_data(writer, s_no, args);
        self.extra.write_data(writer, s_no, args);
        writer.write_field(self.path.to_string());
        self.start.write_data(writer, s_no, args);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CheckId {
    #[serde(rename = "Users.suj.Downloads.ruby-string-interpolation-taint")]
    UsersSujDownloadsRubyStringInterpolationTaint,
}

impl CsvWriter for CheckId{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        writer.write_field(&format!("{:?}",Self::UsersSujDownloadsRubyStringInterpolationTaint)).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct MetaVars{
    abstract_content: Option<String>,
    end: Option<End>,
    propagated_value: Option<PropagatedValue>,
    start: Option<End>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Extra {
    dataflow_trace: Option<DataflowTrace>,
    engine_kind: serde_json::Value,
    fingerprint: String,
    is_ignored: bool,
    lines: String,
    message: serde_json::Value,
    metadata: Option<Meta>,
    metavars: Option<MetaVars>,
    severity: Option<serde_json::Value>,
    validation_state: Option<serde_json::Value>,
}

impl CsvWriter for Extra{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.mode.as_ref().unwrap().as_str() == "sast" {
            // self.severity.write_data(writer, s_no, args);
            if let Some(serde_json::Value::String(x)) = &self.severity {
                writer.write_field(x.to_string()).unwrap();
            }
            match &self.message {
                serde_json::Value::String(x) => {
                    writer.write_field(x.to_string()).unwrap();
                },
                _ => {},
            };
            writer.write_field(self.lines.to_string()).unwrap();
            return;
        }
        // self.dataflow_trace.write_data(writer, s_no, args);
        //self.engine_kind.write_data(writer, s_no, args);
        writer.write_field(self.fingerprint.to_string()).unwrap();
        writer.write_field(self.is_ignored.to_string()).unwrap();
        //self.message.write_data(writer, s_no, args);
        // self.metadata.write_data(writer, s_no, args);
        // self.metavars.write_data(writer, s_no, args);
        //self.severity.write_data(writer, s_no, args);
       // self.validation_state.write_data(writer, s_no, args);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DataflowTrace {
    intermediate_vars: Vec<IntermediateVar>,
    taint_sink: Vec<DataflowTraceTaintSink>,
    taint_source: Vec<DataflowTraceTaintSource>,
}

impl CsvWriter for DataflowTrace{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        self.intermediate_vars
        .iter()
        .map(|x| x.write_data(writer, s_no, args))
        .collect::<()>();
        self.taint_sink
        .iter()
        .map(|x| x.write_data(writer, s_no, args))
        .collect::<()>();
        self.taint_source
        .iter()
        .map(|x| x.write_data(writer, s_no, args))
        .collect::<()>();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IntermediateVar {
    content: String,
    location: LocationElement,
}

impl CsvWriter for IntermediateVar{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        writer.write_field(self.content.to_string()).unwrap();
        self.location.write_data(writer, s_no, args);
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum DataflowTraceTaintSink {
    Enum(TaintS),
    UnionArray(Vec<TaintSinkTaintSink>),
}

impl CsvWriter for DataflowTraceTaintSink{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self {
            Self::Enum(x) => {
                x.write_data(writer, s_no, args);
            },
            Self::UnionArray(x) => {
                x.iter()
                .map(|x| x.write_data(writer, s_no, args))
                .collect::<()>();
            },
        }
    }
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TaintSinkTaintSink {
    LocationElement(LocationElement),
    String(String),
}

impl CsvWriter for TaintSinkTaintSink{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self {
            Self::LocationElement(x) => {
                x.write_data(writer, s_no, args);
            },
            Self::String(x) => {
                writer.write_field(x.to_string()).unwrap();
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaintS {
    #[serde(rename = "CliLoc")]
    CliLoc,
}

impl CsvWriter for TaintS{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum DataflowTraceTaintSource {
    Enum(TaintS),
    UnionArray(Vec<TaintSourceTaintSourceUnion>),
}

impl CsvWriter for DataflowTraceTaintSource{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self {
            Self::Enum(x) => {
                x.write_data(writer, s_no, args);
            },
            Self::UnionArray(x) => {
                x.iter()
                .map(|x| x.write_data(writer, s_no, args))
                .collect::<()>();
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum TaintSourceTaintSourceUnion {
    Enum(TaintSourceEnum),
    LocationElement(LocationElement),
}

impl CsvWriter for TaintSourceTaintSourceUnion{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            return;
        }
        match self {
            Self::Enum(x) => {
                x.write_data(writer, s_no, args);
            },
            Self::LocationElement(x) => {
                x.write_data(writer, s_no, args);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TaintSourceEnum {
    Params,
}

impl CsvWriter for TaintSourceEnum{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum EngineKind {
    #[serde(rename = "OSS")]
    Oss,
}

impl CsvWriter for EngineKind{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    // #[serde(rename = "Potential tainted data in string interpolation detected.")]
    // PotentialTaintedDataInStringInterpolationDetected,
    message: String,
}

impl  CsvWriter for Message{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        // writer.write_field(&format!("{:?}",Self::PotentialTaintedDataInStringInterpolationDetected)).unwrap();
        writer.write_field(self.message.to_string()).unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum List<T>{
    Single(T),
    List(Vec<T>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Meta {
    categoru: Option<String>,
    confidence: Option<String>,
    cve: Option<List<String>>,
    cwe: Option<Vec<String>>,
    #[serde(rename = "cwe2020-top25")]
    cwe2020_top25: Option<bool>,
    #[serde(rename = "cwe2021-top25")]
    cwe2021_top25: Option<bool>,
    #[serde(rename = "cwe2022-top25")]
    cwe2022_top25: Option<bool>,
    ghsa: Option<Vec<String>>,
    impact: Option<String>,
    likelihood: Option<String>,
    #[serde(rename = "publish-date")]
    publish_date: Option<String>,
    #[serde(rename = "dev.semgrep.actions")]
    dev_semgrep_actions: Option<Vec<String>>,
    #[serde(rename = "dev.semgrep.validation-state-actions")]
    dev_semgrep_validation_state_actions: Option<Vec<String>>,
    #[serde(rename = "semgrep.policy")]
    semgrep_policy: Option<Policy>,
    #[serde(rename = "semgrep.ruleset")]
    semgrep_ruleset: Option<Vec<String>>,
    #[serde(rename = "semgrep.ruleset_id")]
    semgrep_ruleset_id: Option<i64>,
    #[serde(rename = "semgrep.url")]
    semgrep_url: Option<String>,
    #[serde(rename = "semgrep.dev")]
    semgrep_dev: Option<SemgrepDev>,
    subcategory: Option<Vec<String>>,
    supersedes: Option<Vec<String>>,
    license: Option<String>,
    masvs: Option<String>,
    #[serde(rename = "owasp-mobile")]
    owasp_mobile: Option<List<String>>,
    owasp: Option<Vec<String>>,
    product: Option<String>,
    references: Option<Vec<String>>,
    secret_type: Option<String>,
    shortlink: Option<String>,
    source: Option<String>,
    #[serde(rename = "source-rule-url")]
    source_rule_url: Option<List<String>>,
    #[serde(rename = "sca-fix-versions")]
    sca_fix_versions: Option<List<HashMap<String,String>>>,
    #[serde(rename = "sca-kind")]
    sca_kind: Option<String>,
    #[serde(rename = "sca-legacy-identifier")]
    sca_legacy_identifier: Option<String>,
    #[serde(rename = "sca-schema")]
    sca_schema: Option<i64>,
    #[serde(rename = "sca-severity")]
    sca_severity: Option<String>,
    #[serde(rename = "vulnerability-class")]
    vulnerability_class: Option<List<String>>,
    #[serde(rename = "sca-vuln-database-identifier")]
    sca_vuln_database_identifier: Option<String>,
    technology: Option<Vec<String>>,
    tags: Option<Vec<String>>,
    author: Option<String>,
    asvs: Option<Asvs>,

}

impl CsvWriter for Meta{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PropagatedValue{
    svalue_abstract_content: Option<String>,
    svalue_end: Option<End>,
    svalue_start: Option<End>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Asvs{
    control_id: Option<String>,
    control_url: Option<String>,
    section: Option<String>,
    version: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Severity {
    #[serde(rename = "ERROR")]
    Error,
}

impl CsvWriter for Severity{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        if args.debug == false {
            writer.write_field(&format!("{:?}",Self::Error)).unwrap();
        }
        
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationState {
    #[serde(rename = "NO_VALIDATOR")]
    NoValidator,
}

impl CsvWriter for ValidationState{
    fn write_data(&self, writer: &mut Writer<File>, mut s_no: u64, args: &Args) {
        
    }
}

fn main() {
    let args = Args::parse();
    if args.file.is_none() {
        println!("Error: Please provide the json file");
        std::process::exit(1);
    }
    if args.output_path.is_none() {
        println!("Error: Please provide the output file name");
        std::process::exit(1);
    }
    if args.mode.is_none() {
        println!("Error: Please specify SAST, SCA or SECRET");
        std::process::exit(1);
    }
    let mut json_data: String = std::fs::read_to_string(args.file.as_ref().unwrap().as_str()).unwrap();
    let mut data: Welcome = serde_json::from_str(json_data.as_str()).unwrap();
    //println!("{:#?}",data);
    let mut writer = WriterBuilder::new()
    .flexible(true)
    .from_path(args.output_path.as_ref().unwrap().as_str()).unwrap();
    let first_row = match args.mode.as_ref().unwrap().as_str() {
        "sast" => {
            [
                "Sno",
                "Rule ID",
                "Severity",
                "Message",
                "Vulnerable Snippet",
                "Path",
                "Line Number",
            ]
        },
        "sca" => {
            panic!("Error: Not Implemented Yet");
        },
        "secret" => {
            panic!("Error: Not Implemented Yet");
        },
        _ => {
            panic!("Error: Unknown Mode");
        },
    };
    writer.write_record(&first_row).unwrap();
    let mut s_no = 0 as u64;
    data.write_data(&mut writer, s_no, &args);

}
