/**
 * Provides call graph analysis for Solidity.
 *
 * This module re-exports all call graph components:
 * - CallResolution: Resolving function calls to targets
 * - InheritanceGraph: Contract inheritance analysis
 * - ExternalCalls: External call detection
 */

import CallResolution
import InheritanceGraph
import ExternalCalls
