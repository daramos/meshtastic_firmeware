#include "VersionFingerprintModule.h"
#include "MeshService.h"
#include "NodeDB.h"
#include <TypeConversions.h>

VersionFingerprintModule *versionFingerprintModule;



VersionFingerprintModule::VersionFingerprintModule()
    : MeshModule("versionfingerprint")
{
    isPromiscuous = true;
    encryptedOk = true;
    LOG_DEBUG("Initialized Version Fingerprint Module");
    
}

std::string VersionFingerprintModule::getVersionedName(uint32_t version, const char * p_node_db_name)
{
    auto max_name_length = sizeof(meshtastic_UserLite::long_name);
    auto version_delimiter = "|v";

    auto major = std::to_string((version & 0xFF0000) >> 16);
    auto minor = std::to_string((version & 0xFF00) >> 8);
    auto point = std::to_string(version & 0xFF);
    auto version_string = major + "." + minor + "." + point;

    auto node_db_name = std::string(p_node_db_name);
    auto version_str_index = node_db_name.find(version_delimiter    );
    if (version_str_index != std::string::npos) {
        node_db_name.resize(version_str_index);
    }

    // Original name needs to be truncated to leave room for the version
    auto versioned_name = node_db_name.substr(0, max_name_length - 14);

    versioned_name += version_delimiter + version_string;
    // Truncate the name to max length, leaving room for null terminator
    versioned_name.resize(max_name_length - 1);

    LOG_DEBUG("Updated versioned name for old_name=%s, new_name=%s\n", p_node_db_name, versioned_name.c_str());
    return versioned_name;
}


ProcessMessage VersionFingerprintModule::handleReceived(const meshtastic_MeshPacket &mp) {
    NodeNum from_nodenum = getFrom(&mp);

    LOG_DEBUG("Received packet for version fingerprint fr=0x%x,to=0x%x,id=0x%x\n", mp.from, mp.to, mp.id);

    if (mp.hop_start) {
        //https://github.com/meshtastic/firmware/blame/c77b89d85c836a9ec2b2d0302c98eb88abcefe3b/src/mesh/generated/meshtastic/mesh.pb.h#L698
        assignFingerprint(from_nodenum, VERSION_2_3_0);
    }
    if (mp.want_ack != 0) {
        assignFingerprint(from_nodenum, VERSION_2_0_8);
    }

    if (mp.which_payload_variant == meshtastic_MeshPacket_decoded_tag) {
        uint8_t struct_buffer[512];
        memset(&struct_buffer, 0, sizeof(struct_buffer));

        if (mp.decoded.portnum == meshtastic_PortNum_NODEINFO_APP) {
            meshtastic_NodeInfoLite *node = nodeDB->getMeshNode(mp.to);
            if (node != nullptr) {
                if (node->user.public_key.size > 0) {
                    LOG_DEBUG("Version Fingerprint, has PKI public key nodenum=0x%x\n", from_nodenum);
                    assignFingerprint(from_nodenum, VERSION_2_5_0);
                }
            }
        }

        if(mp.decoded.portnum == meshtastic_PortNum_NEIGHBORINFO_APP) {
            //https://github.com/meshtastic/firmware/blame/c77b89d85c836a9ec2b2d0302c98eb88abcefe3b/src/mesh/generated/meshtastic/portnums.pb.h#L121
            assignFingerprint(from_nodenum, VERSION_2_1_9);
        }
        if(mp.decoded.portnum == meshtastic_PortNum_ATAK_PLUGIN) {
            //https://github.com/meshtastic/firmware/blame/c77b89d85c836a9ec2b2d0302c98eb88abcefe3b/src/mesh/generated/meshtastic/portnums.pb.h#L124
            assignFingerprint(from_nodenum, VERSION_2_2_22);
        }

        if(mp.decoded.portnum == meshtastic_PortNum_TELEMETRY_APP) {
            if (pb_decode_from_bytes(mp.decoded.payload.bytes, mp.decoded.payload.size, &meshtastic_Telemetry_msg, &struct_buffer)) {
                meshtastic_Telemetry * t = (meshtastic_Telemetry*) &struct_buffer;
                // Check packet for device metrics
                if (t->which_variant == meshtastic_Telemetry_device_metrics_tag && t->variant.device_metrics.uptime_seconds > 0) {
                    //https://github.com/meshtastic/protobufs/blame/c9ca0dbe9cc7105399e0486c07e0601f849b94af/meshtastic/telemetry.proto#L38
                    assignFingerprint(from_nodenum, VERSION_2_3_5);
                }
            }
        }
    }
    updateNodeDB();

    // Our updates here might get overridden by another module running after us. 
    // That's ok, next packet will trigger us again and we can update it then.
    return ProcessMessage::CONTINUE;
}

bool VersionFingerprintModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return getFrom(p) != nodeDB->getNodeNum();
}


void VersionFingerprintModule::assignFingerprint(NodeNum node_num, uint32_t version)
{
    LOG_DEBUG("Assigning version for node=0x%x,version=0x%x\n", node_num, version);
    for (auto & element : node_fingerprints) {
        if(element.node_num == node_num) {
            if(element.version < version) {
                element.version = version;
            }
            return;
        }
    }

    NodeVersionFingerprint fingerprint;
    fingerprint.node_num = node_num;
    fingerprint.version = version;
    node_fingerprints.push_back(fingerprint);
}

void VersionFingerprintModule::updateNodeDB()
{
    for (auto & element : node_fingerprints) {
        auto node = nodeDB->getMeshNode(element.node_num);
        if (node == NULL || !node->has_user) {
            LOG_INFO("Trying to update nodedb versioned name for missing node 0x%x", element.node_num);
            continue;
        }
        auto new_name = getVersionedName(element.version, node->user.long_name);

        if (strncmp(node->user.long_name, new_name.c_str(), sizeof(node->user.long_name))) {
            auto user = TypeConversions::ConvertToUser(node->num,node->user);
            
            strncpy(user.long_name, new_name.c_str(), sizeof(user.long_name)-1);
            // Ensure it's null terminated if strncpy didn't add it
            user.long_name[sizeof(user.long_name)-1] = 0;

            nodeDB->updateUser(node->num, user, node->channel);
        }        
    }
}
