/*
 * CPM IDS Module for VaN3Twin
 * Author: Matthias Krallinger (2026) - FH Salzburg, Bachelor's Thesis
 * Developed with assistance from Claude Opus 4.6 (Anthropic), used as a coding aid.
 *
 * Rule-based Host-based IDS (HIDS) that evaluates received CPM
 * perceived objects using speed plausibility and heading consistency checks.
 */

#ifndef CPM_IDS_MODULE_H
#define CPM_IDS_MODULE_H

#include <unordered_map>
#include <map>
#include <cstdint>
#include <string>
#include <fstream>
#include <cmath>
#include <iostream>
#include "ns3/simulator.h"

namespace ns3 {

struct PreviousObjectState {
    double posX;        // last known x position (0.01m units)
    double posY;        // last known y position (0.01m units)
    double heading;     // last known heading (degrees)
    double timestamp_ms;
};

enum IDSClassification {
    IDS_NORMAL = 0,
    IDS_ANOMALOUS_SPEED = 1,
    IDS_ANOMALOUS_HEADING = 2,
    IDS_ANOMALOUS_BOTH = 3
};

class CPMIDSModule {
public:
    CPMIDSModule()
        : m_speedThresholdKmh(150.0),
          m_headingToleranceDeg(45.0),
          m_logFile("cpm_ids_log.csv"),
          m_enabled(true) {}

    /**
     * @brief Configure IDS thresholds.
     * @param maxSpeedKmh  Maximum plausible speed in km/h
     * @param headingTolDeg  Heading consistency tolerance in degrees
     */
    void configure(double maxSpeedKmh, double headingTolDeg) {
        m_speedThresholdKmh = maxSpeedKmh;
        m_headingToleranceDeg = headingTolDeg;
    }

    void enable() { m_enabled = true; }
    void disable() { m_enabled = false; }
    bool isEnabled() const { return m_enabled; }

    /**
     * @brief Evaluate a perceived object from a received CPM.
     * @param receiverStationId  Station ID of the receiving vehicle
     * @param senderStationId  Station ID of the CPM sender
     * @param objectId  ID of the perceived object
     * @param posX  x position (0.01m units, from xCoordinate.value)
     * @param posY  y position (0.01m units, from yCoordinate.value)
     * @param xSpeed  x velocity (0.01 m/s units)
     * @param ySpeed  y velocity (0.01 m/s units)
     * @param headingDeci  heading in 0.1 degree units (zAngle.value)
     * @return IDSClassification result
     */
    IDSClassification evaluate(long receiverStationId, long senderStationId,
                                long objectId, long posX, long posY,
                                long xSpeed, long ySpeed, long headingDeci) {

        if (!m_enabled) return IDS_NORMAL;

        bool speedAnomaly = false;
        bool headingAnomaly = false;

        // === Speed Plausibility Check ===
        // Convert from 0.01 m/s to km/h: speed_kmh = speed_cms * 0.01 * 3.6 = speed_cms * 0.036
        double scalarSpeedCms = std::sqrt((double)(xSpeed * xSpeed + ySpeed * ySpeed));
        double scalarSpeedKmh = scalarSpeedCms * 0.036;

        if (scalarSpeedKmh > m_speedThresholdKmh || scalarSpeedKmh < 0) {
            speedAnomaly = true;
        }

        // === Heading Consistency Check ===
        double headingDeg = (double)headingDeci / 10.0; // Convert from 0.1 deg to degrees

        // Create unique key for this object from this sender
        uint64_t objectKey = ((uint64_t)senderStationId << 32) | (uint64_t)(objectId & 0xFFFFFFFF);

        auto it = m_previousStates.find(objectKey);
        if (it != m_previousStates.end()) {
            PreviousObjectState &prev = it->second;

            // Compute expected heading from position change
            double dx = (double)(posX - prev.posX);
            double dy = (double)(posY - prev.posY);
            double distance = std::sqrt(dx * dx + dy * dy);

            // Only check heading if object moved significantly (> 1m = 100 units of 0.01m)
            if (distance > 100.0) {
                // atan2 gives radians, convert to degrees [0, 360)
                double expectedHeadingRad = std::atan2(dx, dy); // Note: atan2(dx,dy) for north-based heading
                double expectedHeadingDeg = expectedHeadingRad * 180.0 / M_PI;
                if (expectedHeadingDeg < 0) expectedHeadingDeg += 360.0;

                // Compute angular deviation (circular)
                double deviation = std::abs(headingDeg - expectedHeadingDeg);
                if (deviation > 180.0) deviation = 360.0 - deviation;

                if (deviation > m_headingToleranceDeg) {
                    headingAnomaly = true;
                }
            }
        }

        // Update stored state for next check
        PreviousObjectState newState;
        newState.posX = posX;
        newState.posY = posY;
        newState.heading = headingDeg;
        newState.timestamp_ms = Simulator::Now().GetMilliSeconds();
        m_previousStates[objectKey] = newState;

        // Determine classification
        IDSClassification result = IDS_NORMAL;
        if (speedAnomaly && headingAnomaly) result = IDS_ANOMALOUS_BOTH;
        else if (speedAnomaly) result = IDS_ANOMALOUS_SPEED;
        else if (headingAnomaly) result = IDS_ANOMALOUS_HEADING;

        // Log the evaluation
        logEvaluation(receiverStationId, senderStationId, objectId,
                      scalarSpeedKmh, headingDeg, result);

        return result;
    }

    void setLogFile(const std::string &filename) { m_logFile = filename; }

    void closeLog() { closeSharedStream(m_logFile); }

private:
    /**
     * @brief Shared log streams (one per file name) for all module instances.
     *        Every vehicle has its own module instance; previously each instance
     *        opened the same CSV with ios::trunc, so instances overwrote each
     *        other and only the last one's rows survived.
     */
    static std::map<std::string, std::ofstream>& sharedStreams() {
        static std::map<std::string, std::ofstream> streams;
        return streams;
    }
    static std::ofstream& sharedStream(const std::string &file, const std::string &header) {
        auto &streams = sharedStreams();
        auto it = streams.find(file);
        if (it == streams.end()) {
            it = streams.emplace(file, std::ofstream(file, std::ios::out | std::ios::trunc)).first;
            it->second << header << std::endl;
        }
        return it->second;
    }
    static void closeSharedStream(const std::string &file) {
        auto &streams = sharedStreams();
        auto it = streams.find(file);
        if (it != streams.end() && it->second.is_open()) it->second.close();
    }

    void logEvaluation(long receiverId, long senderId, long objectId,
                       double speedKmh, double headingDeg, IDSClassification result) {
        std::ofstream &ofs = sharedStream(m_logFile,
            "timestamp_ms,receiver_id,sender_id,object_id,"
            "speed_kmh,heading_deg,classification");
        std::string classStr;
        switch (result) {
            case IDS_NORMAL:            classStr = "normal"; break;
            case IDS_ANOMALOUS_SPEED:   classStr = "anomalous_speed"; break;
            case IDS_ANOMALOUS_HEADING: classStr = "anomalous_heading"; break;
            case IDS_ANOMALOUS_BOTH:    classStr = "anomalous_both"; break;
        }
        ofs << Simulator::Now().GetMilliSeconds() << ","
              << receiverId << ","
              << senderId << ","
              << objectId << ","
              << speedKmh << ","
              << headingDeg << ","
              << classStr << std::endl;
    }

    double m_speedThresholdKmh;
    double m_headingToleranceDeg;
    std::string m_logFile;
    bool m_enabled;

    // Store previous state of each perceived object (keyed by sender+objectId)
    std::unordered_map<uint64_t, PreviousObjectState> m_previousStates;
};

} // namespace ns3

#endif // CPM_IDS_MODULE_H