/*
 * CPM Evaluation Module for VaN3Twin
 * Author: Matthias Krallinger (2026) - FH Salzburg, Bachelor's Thesis
 * Developed with assistance from Claude Opus 4.6 (Anthropic), used as a coding aid.
 *
 * Confusion-matrix-based evaluation pipeline that compares IDS
 * classification decisions against ground-truth attack labels.
 */

#ifndef CPM_EVAL_MODULE_H
#define CPM_EVAL_MODULE_H

#include <string>
#include <fstream>
#include <iostream>
#include <cmath>

namespace ns3 {

class CPMEvalModule {
public:
    CPMEvalModule()
        : m_tp(0), m_fp(0), m_tn(0), m_fn(0),
          m_logFile("cpm_eval_log.csv"),
          m_fileOpened(false) {}

    /**
     * @brief Record one evaluation result.
     * @param wasManipulated  Ground truth: was this object's CPM actually manipulated?
     * @param flaggedAnomalous  IDS decision: was this object flagged as anomalous?
     */
    void record(bool wasManipulated, bool flaggedAnomalous,
                double timestamp_ms = 0, long senderId = 0, long objectId = 0) {
        if (wasManipulated && flaggedAnomalous) m_tp++;
        else if (!wasManipulated && flaggedAnomalous) m_fp++;
        else if (!wasManipulated && !flaggedAnomalous) m_tn++;
        else if (wasManipulated && !flaggedAnomalous) m_fn++;

        // Log each evaluation
        if (!m_fileOpened) {
            m_ofs.open(m_logFile, std::ios::out | std::ios::trunc);
            m_ofs << "timestamp_ms,sender_id,object_id,ground_truth,ids_decision,result"
                  << std::endl;
            m_fileOpened = true;
        }
        std::string gt = wasManipulated ? "manipulated" : "normal";
        std::string ids = flaggedAnomalous ? "anomalous" : "normal";
        std::string result;
        if (wasManipulated && flaggedAnomalous) result = "TP";
        else if (!wasManipulated && flaggedAnomalous) result = "FP";
        else if (!wasManipulated && !flaggedAnomalous) result = "TN";
        else result = "FN";

        m_ofs << timestamp_ms << "," << senderId << "," << objectId << ","
              << gt << "," << ids << "," << result << std::endl;
    }

    // Metrics
    long getTP() const { return m_tp; }
    long getFP() const { return m_fp; }
    long getTN() const { return m_tn; }
    long getFN() const { return m_fn; }

    double getPrecision() const {
        if (m_tp + m_fp == 0) return 0.0;
        return (double)m_tp / (double)(m_tp + m_fp);
    }

    double getRecall() const {
        if (m_tp + m_fn == 0) return 0.0;
        return (double)m_tp / (double)(m_tp + m_fn);
    }

    double getFPR() const {
        if (m_fp + m_tn == 0) return 0.0;
        return (double)m_fp / (double)(m_fp + m_tn);
    }

    double getAccuracy() const {
        long total = m_tp + m_fp + m_tn + m_fn;
        if (total == 0) return 0.0;
        return (double)(m_tp + m_tn) / (double)total;
    }

    /**
     * @brief Print the full evaluation summary to stdout.
     */
    void printSummary() const {
        std::cout << "\n========== CPM IDS Evaluation Summary ==========" << std::endl;
        std::cout << "Confusion Matrix:" << std::endl;
        std::cout << "  TP: " << m_tp << "  |  FP: " << m_fp << std::endl;
        std::cout << "  FN: " << m_fn << "  |  TN: " << m_tn << std::endl;
        std::cout << "Metrics:" << std::endl;
        std::cout << "  Precision: " << getPrecision() << std::endl;
        std::cout << "  Recall:    " << getRecall() << std::endl;
        std::cout << "  FPR:       " << getFPR() << std::endl;
        std::cout << "  Accuracy:  " << getAccuracy() << std::endl;
        std::cout << "  Total evaluated: " << (m_tp + m_fp + m_tn + m_fn) << std::endl;
        std::cout << "================================================\n" << std::endl;
    }

    /**
     * @brief Write summary to a CSV file.
     */
    void writeSummaryCSV(const std::string &filename) const {
        std::ofstream f(filename, std::ios::out | std::ios::trunc);
        f << "metric,value" << std::endl;
        f << "TP," << m_tp << std::endl;
        f << "FP," << m_fp << std::endl;
        f << "TN," << m_tn << std::endl;
        f << "FN," << m_fn << std::endl;
        f << "Precision," << getPrecision() << std::endl;
        f << "Recall," << getRecall() << std::endl;
        f << "FPR," << getFPR() << std::endl;
        f << "Accuracy," << getAccuracy() << std::endl;
        f.close();
    }

    void setLogFile(const std::string &filename) { m_logFile = filename; }

    void closeLog() {
        if (m_fileOpened) {
            m_ofs.close();
            m_fileOpened = false;
        }
    }

private:
    long m_tp, m_fp, m_tn, m_fn;
    std::string m_logFile;
    std::ofstream m_ofs;
    bool m_fileOpened;
};

} // namespace ns3

#endif // CPM_EVAL_MODULE_H
