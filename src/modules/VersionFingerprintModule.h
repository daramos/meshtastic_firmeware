#pragma once
#include "MeshModule.h"

#define VERSION_TO_BYTES(A, B, C)  ( ( ( (A)&0xFF ) << 16 )|( ( (B)&0xFF ) << 8 )|( ( (C)&0xFF ) ) )
#define VERSION_UNKNOWN (0)
#define VERSION_2_0_8 VERSION_TO_BYTES(2,0,8)
#define VERSION_2_0_14 VERSION_TO_BYTES(2,0,14)
#define VERSION_2_1_9 VERSION_TO_BYTES(2,1,9)
#define VERSION_2_2_22 VERSION_TO_BYTES(2,2,22)
#define VERSION_2_3_0 VERSION_TO_BYTES(2,3,0)
#define VERSION_2_3_5 VERSION_TO_BYTES(2,3,5)
#define VERSION_2_5_0 VERSION_TO_BYTES(2,5,0)


struct NodeVersionFingerprint
{
    NodeNum node_num;
    uint32_t version;
    
};

/*
 * VersionFingerprint module to fingerprint node versions
 */
class VersionFingerprintModule : public MeshModule
{

  public:
    /*
     * Expose the constructor
     */
    VersionFingerprintModule();
    std::vector<NodeVersionFingerprint> node_fingerprints;
    
  protected:
    virtual ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

    virtual bool wantPacket(const meshtastic_MeshPacket *p) override;

    void assignFingerprint(NodeNum node_num, uint32_t version);

    void updateNodeDB();

    std::string getVersionedName(uint32_t version, const char * p_node_db_name);
};
extern VersionFingerprintModule *versionFingerprintModule;