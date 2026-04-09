/*
 * CPM Attack Module for VaN3Twin
 * Author: Matthias Krallinger (2026) - FH Salzburg, Bachelor's Thesis
 * Developed with assistance from Claude Opus 4.6 (Anthropic), used as a coding aid.
 *
 * This module intercepts CPM perceived object attributes before encoding
 * and applies configurable speed/heading manipulation. Ground-truth values
 * are logged alongside manipulated values for evaluation.
 */

#ifndef CPM_ATTACK_MODULE_H
#define CPM_ATTACK_MODULE_H

#include <set>
#include <string>
#include <fstream>
#include <cmath>
#include <iostream>
#include "ns3/simulator.h"

namespace ns3 {

struct AttackLogEntry {
    double timestamp_ms;
    long senderStationId;
    long objectId;
    double originalSpeedX;   // original xSpeed (0.01 m/s units)
    double originalSpeedY;   // original ySpeed (0.01 m/s units)
    double originalHeading;  // original heading (degrees)
    double attackSpeedX;     // manipulated xSpeed
    double attackSpeedY;     // manipulated ySpeed
    double attackHeading;    // manipulated heading (degrees)
};

class CPMAttackModule {
public:
    CPMAttackModule()
        : m_enabled(false),
          m_speedOffsetKmh(0.0),
          m_headingOffsetDeg(0.0),
          m_logFile("cpm_attack_log.csv"),
          m_fileOpened(false) {}

    /**
     * @brief Enable attack mode for this vehicle.
     * @param speedOffsetKmh  Speed offset in km/h (e.g., +100)
     * @param headingOffsetDeg  Heading offset in degrees (e.g., +90)
     */
    void enable(double speedOffsetKmh, double headingOffsetDeg) {
        m_enabled = true;
        m_speedOffsetKmh = speedOffsetKmh;
        m_headingOffsetDeg = headingOffsetDeg;
    }

    void disable() { m_enabled = false; }
    bool isEnabled() const { return m_enabled; }
    double getSpeedOffsetKmh() const { return m_speedOffsetKmh; }
    double getHeadingOffsetDeg() const { return m_headingOffsetDeg; }

    /**
     * @brief Apply manipulation to speed components (in 0.01 m/s units).
     * @param xSpeed  Original x velocity component
     * @param ySpeed  Original y velocity component
     * @param[out] attackXSpeed  Manipulated x velocity
     * @param[out] attackYSpeed  Manipulated y velocity
     */
    void manipulateSpeed(long xSpeed, long ySpeed, long &attackXSpeed, long &attackYSpeed) {
        // Convert offset from km/h to 0.01 m/s: km/h * (1000/3600) * 100 = km/h * 27.778
        double offsetCms = m_speedOffsetKmh * 27.778;

        // Compute original scalar speed
        double scalarSpeed = std::sqrt((double)(xSpeed * xSpeed + ySpeed * ySpeed));

        if (scalarSpeed > 0.001) {
            // Scale both components proportionally
            double newSpeed = scalarSpeed + offsetCms;
            if (newSpeed < 0) newSpeed = 0;
            double scaleFactor = newSpeed / scalarSpeed;
            attackXSpeed = (long)(xSpeed * scaleFactor);
            attackYSpeed = (long)(ySpeed * scaleFactor);
        } else {
            // Vehicle is nearly stationary — add offset to x component only
            attackXSpeed = (long)(offsetCms);
            attackYSpeed = ySpeed;
        }
    }

    /**
     * @brief Apply manipulation to heading (in degrees, before DECI multiplication).
     * @param headingDeg  Original heading in degrees
     * @return Manipulated heading in degrees, wrapped to [0, 360)
     */
    double manipulateHeading(double headingDeg) {
        double newHeading = headingDeg + m_headingOffsetDeg;
        // Wrap to [0, 360)
        newHeading = std::fmod(newHeading, 360.0);
        if (newHeading < 0) newHeading += 360.0;
        return newHeading;
    }

    /**
     * @brief Log an attack entry (both original and manipulated values).
     *        Called on the sender side for attacker vehicles only.
     */
    void logAttack(long senderStationId, long objectId,
                   long origXSpeed, long origYSpeed, double origHeading,
                   long atkXSpeed, long atkYSpeed, double atkHeading) {
        if (!m_fileOpened) {
            m_ofs.open(m_logFile, std::ios::out | std::ios::trunc);
            m_ofs << "timestamp_ms,sender_id,object_id,"
                  << "orig_xSpeed,orig_ySpeed,orig_heading_deg,"
                  << "atk_xSpeed,atk_ySpeed,atk_heading_deg" << std::endl;
            m_fileOpened = true;
        }
        m_ofs << Simulator::Now().GetMilliSeconds() << ","
              << senderStationId << ","
              << objectId << ","
              << origXSpeed << "," << origYSpeed << "," << origHeading << ","
              << atkXSpeed << "," << atkYSpeed << "," << atkHeading << std::endl;
    }
    /**
     * @brief Log a ground-truth entry for a received CPM object.
     *        Records the received (possibly manipulated) values alongside
     *        the ground-truth label (manipulated vs. normal).
     *        Called on the receiver side for all incoming CPMs.
     */
    void logGroundTruth(long senderStationId, long objectId,
                        long xSpeed, long ySpeed, double headingDeg,
                        bool wasManipulated) {
        if (!m_gtFileOpened) {
            m_gtOfs.open(m_gtLogFile, std::ios::out | std::ios::trunc);
            m_gtOfs << "timestamp_ms,sender_id,object_id,"
                    << "xSpeed,ySpeed,heading_deg,manipulated" << std::endl;
            m_gtFileOpened = true;
        }
        m_gtOfs << Simulator::Now().GetMilliSeconds() << ","
                << senderStationId << ","
                << objectId << ","
                << xSpeed << "," << ySpeed << "," << headingDeg << ","
                << (wasManipulated ? "true" : "false") << std::endl;
    }

    void setLogFile(const std::string &filename) { m_logFile = filename; }
    void setGroundTruthLogFile(const std::string &filename) { m_gtLogFile = filename; }

    void closeGroundTruthLog() {
        if (m_gtFileOpened) {
            m_gtOfs.close();
            m_gtFileOpened = false;
        }
    }
    void closeLog() {
        if (m_fileOpened) {
            m_ofs.close();
            m_fileOpened = false;
        }
    }

private:
    bool m_enabled;
    double m_speedOffsetKmh;
    double m_headingOffsetDeg;
    std::string m_logFile;
    std::ofstream m_ofs;
    bool m_fileOpened;
    std::string m_gtLogFile  = "cpm_groundtruth_log.csv";
    std::ofstream m_gtOfs;
    bool m_gtFileOpened      = false;
};

} // namespace ns3

#endif // CPM_ATTACK_MODULE_H
